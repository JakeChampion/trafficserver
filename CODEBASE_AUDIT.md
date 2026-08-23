# Apache Traffic Server — Codebase Audit

_Multi-agent review across 12 lenses. Every critical/high memory-safety and concurrency claim was independently re-verified by an adversarial agent that tried to refute it; only claims that survived are marked ✓verified._

## Scope & method

The audit ran 12 specialized reviewers in parallel over `src/` and `include/` (~378k lines of C++20), each reading real code with grep/read before reporting. Findings tagged as critical or high in a memory-safety, race, or overflow category were then handed to a separate verifier agent instructed to disprove them by tracing callers, locking, reference counts, and continuation lifetimes. **9 of 9 verified claims were confirmed; none were refuted.**

## Headline results

- **1 critical**, **11 high**, **34 medium**, **19 low** findings (65 total).
- The single **critical** and most of the confirmed memory-safety bugs are concentrated in the **HTTP/3 QPACK decoder** (`src/proxy/http3/QPACK.cc`) — attacker-facing whenever HTTP/3 is enabled.
- The HTTP/1.x state machine, HTTP/2 core, cache, and the net-core lifetime model are, by contrast, mature and mostly sound; the reviewers confirmed the deliberate safety designs there and found few holes.
- Notable non-memory issues: an **RFC 9111 cache-correctness violation** (qualified `private=`/`no-cache=` discarded → shared cache may store private responses), an **O(n²) header-parse** amplification, and a **documented-but-unfixed UAF race** in log-config reload.

## Confirmed memory-safety / concurrency bugs (verified)

Each row was traced end-to-end by an adversarial verifier and survived. The QPACK header-prefix bug was found **independently by two separate lenses** (HTTP/3 and security), which is why it carries the most corroboration.

| Sev | Bug | Location |
|-----|-----|----------|
| **critical** | QPACK static-table lookup indexes `STATIC_HEADER_FIELDS[index]` with no bounds check → OOB read on attacker input | `src/proxy/http3/QPACK.cc:1222` |
| high | QPACK header-block use-after-free: `DecodeRequest` stashes a raw pointer into a per-transaction frame that is freed/reused before a blocked decode resumes | `src/proxy/http3/QPACK.cc:295` |
| high | QPACK inverted error check (`ret < 0 && tmp > LIMIT`) lets integer/string decode failures corrupt `pos`/`remain_len` → OOB reads (found by 2 lenses) | `src/proxy/http3/QPACK.cc:923` |
| high | SSLNetVConnection blind-tunnel path ignores `readSignalDone()` return and dereferences a VC that the trampoline may have freed | `src/iocore/net/SSLNetVConnection.cc:559` |
| high | HostDB pending-DNS waiter can be called back twice (30s timeout races DNS completion) → second `EVENT_HOST_DB_LOOKUP` into an already-torn-down SM | `src/iocore/hostdb/HostDB.cc:815` |
| high | Data race on shared `RemapPluginInfo::_tempContext` corrupts plugin context save/restore across concurrent `doRemap` calls | `src/proxy/http/remap/RemapPluginInfo.cc:275` |
| high | Continuations created off plugin context (e.g. from `TSThreadCreate` threads) take no DSO refcount → use-after-`dlclose` on remap reload | `src/api/InkAPI.cc:3407` |
| high | Documented-but-unfixed UAF race between `TSTextLogObjectCreate` and log-config reload | `src/proxy/logging/Log.cc:133` |

---

## Findings by area

### Network Core & Event-System Object Lifetime

_The net-core object-lifetime model here is deliberate and mostly sound: closes are deferred via the `recursion` counter so that a callback that calls `do_io_close()` frees the VC only after the signal helper unwinds (`read_signal_and_update`/`write_signal_and_update` return EVENT_DONE when they free), timeouts are cop-driven (no dangling per-VC Events), and epoll/async registrations are torn down before free. The signal helpers document that they may free `this` and callers are expected to check for EVENT_DONE. The strongest defect is a spot in the SSL blind-tunnel read path that ignores that contract and dereferences a potentially-freed VC. A secondary latent crash exists in the outbound connect startEvent cancel path, which frees a VC through a NetHandler code path before the VC has ever been attached to a NetHandler._

#### [HIGH ✓verified] Use-after-free in SSLNetVConnection::net_read_io blind-tunnel path: readSignalDone() return ignored, then `this` dereferenced
**`src/iocore/net/SSLNetVConnection.cc:559`** · _use-after-free_

In the SNI-decided blind-tunnel branch, `this->readSignalDone(VC_EVENT_READ_COMPLETE, nh)` is called and its return value discarded, then lines 565-585 continue to dereference `this` (getSSLHandShakeComplete(), sslHandshakeStatus, read.vio, free_handshake_buffers(), a second readSignalDone). readSignalDone -> read_signal_done -> read_signal_and_update invokes the read VIO continuation, which for this VC is the SSLNextProtocolTrampoline (installed by the zero-length do_io_read in SSLNextProtocolAccept::mainEvent). On VC_EVENT_READ_COMPLETE the trampoline reroutes to the negotiated endpoint and, when there is no endpoint, calls `netvc->do_io_close()` (SSLNextProtocolAccept.cc:129); send_plugin_event to the endpoint can also close synchronously. do_io_close during the callback sets closed=1 (deferred because recursion==1), and when read_signal_and_update unwinds it calls nh->free_netevent(this), returning the VC to its allocator (read_signal_and_update returns EVENT_DONE). Control then returns to line 559 with the discarded EVENT_DONE and executes line 565 on freed memory. Every other readSignalDone/_readSignalError call in this file that could free the VC is immediately followed by `return`; only this one keeps touching `this`. The comment at 555-558 shows the author knows the trampoline runs here but assumes the VC survives.

```
559: this->readSignalDone(VC_EVENT_READ_COMPLETE, nh);
565: if (!this->getSSLHandShakeComplete()) {
566:   this->sslHandshakeStatus = SSLHandshakeStatus::SSL_HANDSHAKE_DONE;
... 578: this->free_handshake_buffers();  (all on possibly-freed `this`)
// SSLNextProtocolAccept.cc:128-130: // No handler ... netvc->do_io_close();
```

**Fix:** Capture the return of readSignalDone at line 559 and return immediately if it is EVENT_DONE (VC freed), before any further use of `this`, mirroring the pattern used everywhere else in net_read_io (e.g. lines 668, 600).

**Verification:** Traced end-to-end. At SSLNetVConnection.cc:559 the blind-tunnel branch calls readSignalDone(VC_EVENT_READ_COMPLETE) whose read.vio.cont is the SSLNextProtocolTrampoline installed by SSLNextProtocolAccept::mainEvent (SSLNextProtocolAccept.cc:158); read_signal_and_update invokes it synchronously (mutex match, UnixNetVConnection.cc:85) after recursion++ (→1). In the SNI blind-tunnel case no ALPN endpoint is selected so netvc->endpoint() (TLSALPNSupport.h:52) is null and endpoint_cont becomes the port's default acceptor. send_plugin_event runs handleEvent synchronously under a blocking lock (SSLNextProtocolAccept.cc:34-39); this is the first IpAllow check, so a denied client makes HttpSessionAccept::accept return false → netvc->do_io_close() (HttpSessionAccept.cc:103). Because recursion==1, do_io_close sets close_inline=false and only marks closed=1 (UnixNetVConnection.cc:273-294); on unwind, read_signal_and_update does !--recursion && closed → nh->free_netevent(vc), returning the VC to its allocator and EVENT_DONE (UnixNetVConnection.cc:105-109). That EVENT_DONE is discarded at line 559, and line 565 (this->getSSLHandShakeComplete()) through line 578 (free_handshake_buffers) dereference freed this. The explicit no-endpoint do_io_close (SSLNextProtocolAccept.cc:129) is a second synchronous-close trigger. Mutex-at-dispatch does not protect this because the free is synchronous within the same frame. recursion is 0 on normal NetHandler dispatch, so the innermost frame triggers the free rather than deferring past line 565. Sibling readSignalDone/_readSignalError calls at 703/712/717 are safe because they break straight out of the switch/function with no subsequent this deref (verified 714-721); only line 559 keeps touching this. Bug is conditional on synchronous endpoint rejection (IpAllow deny is concretely reachable), but fully traceable in that case.

#### [MEDIUM] UnixNetVConnection::startEvent frees a not-yet-attached VC via NetHandler::free_netevent (nh/thread still null) on the cancelled connect path
**`src/iocore/net/UnixNetVConnection.cc:961`** · _use-after-free_

On the outbound connect slow path, connect_re() does `t->schedule_imm(vc)` with handler startEvent without ever calling connectUp/startIO, so vc->nh and vc->thread are still null (NetVConnection.h:347 initializes thread=nullptr; nh is set only in NetHandler::startIO). If the caller cancels the returned Action (&vc->action_) before startEvent runs, startEvent takes the `action_.cancelled` branch and calls `get_NetHandler(e->ethread)->free_netevent(this)`. free_netevent immediately asserts `ne->get_thread() == t` (null != t) and then stopIO asserts `ne->nh == this` (null != the NetHandler) — an ink_release_assert abort — and semantically it also runs stopCop/stopIO against queues the VC was never inserted into. The correct teardown for a VC with no NetHandler is free_thread(t); connectUp's own failure path already does exactly this: `if (nullptr != nh) nh->free_netevent(this); else this->free_thread(t);` (lines 1192-1196). startEvent does not make that distinction.

```
958:  if (!action_.cancelled) {
959:    connectUp(e->ethread, NO_FD);
960:  } else {
961:    get_NetHandler(e->ethread)->free_netevent(this);
962:  }
// free_netevent: ink_release_assert(ne->get_thread() == t); ... stopIO: ink_release_assert(ne->nh == this);
```

**Fix:** In the cancelled branch, free the VC the same way connectUp's fail path does: if `nh` is null call `this->free_thread(e->ethread)`, otherwise `nh->free_netevent(this)`.


### HTTP/2 & HTTP/3 (QPACK / HPACK / flow control)

_The HTTP/2 core (Http2ConnectionState/Http2Stream/HPACK) is mature and generally solid on flow-control accounting, frame-flood mitigations (CONTINUATION/RST/SETTINGS/empty-frame per-minute caps), stream lifecycle reentrancy, and HPACK dynamic-table bounds. The serious problems are concentrated in the HTTP/3 QPACK implementation (src/proxy/http3/QPACK.cc), which is attacker-facing when HTTP/3 is enabled: an unchecked static-table index lookup (OOB read), a use-after-free of the header block when a decode is blocked and later resumed, and a pervasive inverted error-check idiom that turns decode failures into pointer/length corruption. HTTP/2 has one minor DATA-padding off-by-one. Findings are ranked by severity._

#### [CRITICAL ✓verified] QPACK static-table lookup indexes the array with no bounds check (OOB read)
**`src/proxy/http3/QPACK.cc:1222`** · _memory-bug_

QPACK::StaticTable::lookup(uint16_t index, ...) dereferences STATIC_HEADER_FIELDS[index] with no range check, but STATIC_HEADER_FIELDS has only 99 entries and index is attacker-controlled (a QPACK integer up to 0xFFFF). It is reached directly from the header-block decode path for any 'Indexed Header Field' / 'Literal Header Field With Name Reference' that sets the static (T) bit: _decode_indexed_header_field (buf[0]&0x40 -> StaticTable::lookup(index) at line 709) and _decode_literal_header_field_with_name_ref (buf[0]&0x10 -> line 756), as well as the encoder-stream 'Insert With Name Reference' handler (line 1156). A single crafted HEADERS field with a static index >= 99 reads past the array; the garbage Header returned supplies a wild name/value pointer and length that are then passed to _attach_header -> field_create/value_set (std::string_view{name, name_len}), causing an out-of-bounds read of attacker-influenced size and near-certain crash or header-memory disclosure. Note also that the encoder-stream handler at line 1156 calls StaticTable::lookup(index) unconditionally, ignoring the is_static flag it just parsed, so even dynamic-table name references hit this unchecked static path.

```
1220: QPACK::StaticTable::lookup(uint16_t index, const char **name, ...) {
1222:   const Header &header = STATIC_HEADER_FIELDS[index];   // no check index < 99
...
708:   if (buf[0] & 0x40) { // Static table
709:     result = StaticTable::lookup(index, &name, &name_len, &value, &value_len);
...
1156:   StaticTable::lookup(index, &name, &name_len, &dummy, &dummy_len); // is_static ignored
```

**Fix:** Bounds-check index against countof(STATIC_HEADER_FIELDS) in the by-index StaticTable::lookup and return MatchType::NONE (decoding error) when out of range; also honor is_static at line 1156 by looking up the dynamic table when the static bit is clear.

**Verification:** STATIC_HEADER_FIELDS[] (QPACK.cc:41-139) has exactly 99 entries (indices 0-98). StaticTable::lookup(uint16_t index,...) at line 1222 indexes STATIC_HEADER_FIELDS[index] with no range check and always returns {index, MatchType::EXACT} at line 1227, so the callers' `if (result.match_type != EXACT) return -1` guards (lines 714, 761) never reject an out-of-range index. The index originates from xpack_decode_integer (src/proxy/hdrs/XPACK.cc), a uint64_t decoded from the wire whose only cap is UINT64_MAX overflow — nothing binds it to the static-table size; it is then truncated to uint16_t (0..65535) at the lookup signature. Reached on the normal HTTP/3 header-block decode path: _decode_header (line 915) dispatches per-field, _decode_indexed_header_field sets the static bit at buf[0]&0x40 -> lookup(index) at line 709, and _decode_literal_header_field_with_name_ref at buf[0]&0x10 -> line 756. A crafted field with static index >= 99 (e.g. bytes 0xFF 0x24 giving index 99) reads past the array; the garbage Header's name/name_len then flow into _attach_header. This is synchronous parsing of attacker bytes — no mutex/continuation-lifetime protection applies. The encoder-stream Insert With Name Reference at line 1156 also calls StaticTable::lookup(index) unconditionally, ignoring the is_static flag parsed at line 1150, adding a third unchecked sink. No bounds check, assert, or clamp exists anywhere on the path.

#### [HIGH ✓verified] Use-after-free of QPACK header block when decode is blocked then resumed
**`src/proxy/http3/QPACK.cc:295`** · _use-after-free_

When a QPACK-encoded HEADERS block references dynamic-table entries not yet received, QPACK::decode() stashes a DecodeRequest holding the raw header_block pointer and length and returns 1 (blocked). That pointer comes from Http3HeadersFrame::header_block(), which returns _header_block, an ats_malloc'd buffer owned by the frame. The frame handed to Http3HeaderVIOAdaptor::handle_frame is the shared, reusable per-type frame returned by Http3FrameFactory::fast_create (stored in _reusable_frames[type]); on the next HEADERS frame on the connection the dispatcher calls fast_create again, which invokes frame->reset(reader) -> ~Http3HeadersFrame() -> ats_free(_header_block), freeing exactly the buffer the pending DecodeRequest still points at. When the encoder stream later unblocks the request, QPACK::_resume_decode() calls _decode(..., r->header_block(), r->header_block_len(), ...) on the freed buffer, a use-after-free of attacker-controlled data on the HTTP/3 request path (and if the freed block is reallocated, headers are decoded from unrelated memory).

```
QPACK.cc 294: if (this->_add_to_blocked_list(new DecodeRequest(largest_reference, thread, cont, stream_id, header_block, header_block_len, hdr)))
QPACK.cc 1039: this->_decode(r->thread(), r->continuation(), r->stream_id(), r->header_block(), r->header_block_len(), r->hdr());
Http3Frame.cc 323: void Http3HeadersFrame::reset(IOBufferReader &reader){ this->~Http3HeadersFrame(); new (this) Http3HeadersFrame(reader); }
Http3Frame.cc 295: if (this->_header_block_uptr == nullptr) { ats_free(this->_header_block); }
Http3Frame.cc 572: std::shared_ptr<Http3Frame> frame = this->_reusable_frames[static_cast<uint8_t>(type)]; ... 580: frame->reset(reader);
```

**Fix:** Copy the header block into the DecodeRequest (own the bytes) instead of storing a raw pointer into the reusable frame, or retain the shared_ptr<const Http3Frame> for the lifetime of the blocked request so the buffer cannot be freed/reset while a decode is pending.

**Verification:** Traced end-to-end. QPACK::decode (QPACK.cc:295) stashes a DecodeRequest holding only the raw header_block pointer (DecodeRequest stores const uint8_t* _header_block, QPACK.h:182-183; no copy, no shared_ptr). That pointer is Http3HeadersFrame::_header_block, an ats_malloc'd buffer allocated in _parse (Http3Frame.cc:350) and owned by the per-transaction reusable frame returned by Http3FrameFactory::fast_create (_reusable_frames[HEADERS], Http3Frame.cc:572; factory is a member of Http3FrameDispatcher which is a member of Http3Transaction, Http3FrameDispatcher.h:51 / Http3Transaction.h:154). Dropping _current_frame (dispatcher line 140) does not free the buffer because _reusable_frames keeps a ref. A subsequent HEADERS frame on the SAME stream (trailers) drives fast_create->frame->reset(reader) (Http3Frame.cc:580)->~Http3HeadersFrame(), and since a reader-parsed frame has _header_block_uptr==nullptr the dtor ats_free(_header_block) (Http3Frame.cc:295-297) frees exactly the buffer the pending DecodeRequest points at. This free occurs inside fast_create before handle_frame. When encoder-stream inserts later arrive, _resume_decode (QPACK.cc:1039) calls _decode on the freed buffer -> UAF of attacker-controlled data. The only candidate guard, _max_blocking_streams (default 0, QPACK.h:201; rejects stash at QPACK.cc:1001), is defeated because Http3SettingsHandler applies the remote peer's SETTINGS QPACK_BLOCKED_STREAMS to remote_qpack — the decoding QPACK (Http3SettingsHandler.cc:72-74; remote_qpack is 'QPACK for decoding', Http3Session.h:94) — so the attacker enables the blocked list by advertising a nonzero value. All processing is on the single connection thread, so no mutex/dispatch guard prevents the lifetime bug; nothing cancels or copies the DecodeRequest on frame reuse.

**Verifier correction:** The claim says the reusable frame is reset 'on the next HEADERS frame on the connection.' In fact the frame factory (Http3FrameFactory _frame_factory) is a member of Http3FrameDispatcher, which is a per-transaction member of Http3Transaction — so the reuse/free is triggered specifically by a later HEADERS frame on the SAME request stream (i.e. trailers), not by HEADERS on any stream of the connection. This narrows the trigger but the bug remains attacker-reachable: a malicious client sends request HEADERS referencing an un-inserted dynamic-table entry (decode blocks), then DATA, then a trailer HEADERS (frees the buffer), then delayed encoder-stream inserts (resume -> UAF). Also worth noting: the value that enables blocking comes via a likely-separate bug where the remote peer's QPACK_BLOCKED_STREAMS setting is applied to the decoder side, which is what makes _max_blocking_streams>0 attacker-controllable.

#### [HIGH ✓verified] Inverted error check in QPACK integer/string decode leads to pos/remain_len corruption
**`src/proxy/http3/QPACK.cc:923`** · _memory-bug_

Multiple QPACK decode sites use the idiom `if ((ret = xpack_decode_integer/string(...)) < 0 && tmp > LIMIT) return err;`. The `&&` should be `||`: when the decode fails (ret < 0) but the partially-decoded value is small (the common case, e.g. tmp <= 0xFFFF), the error is NOT returned. Execution then does `pos += ret` and `remain_len -= ret` with a negative ret, moving pos before the buffer start and underflowing remain_len to a huge size_t, after which the per-instruction sub-decoders read pos[0] and treat pos+remain_len as the end, producing out-of-bounds reads. In _decode_header the prefix scratch `tmp` is also uninitialized (line 922), so on the empty/truncated-buffer error path the branch is taken based on an indeterminate value. The same inverted pattern appears in QPACK::decode (line 287) and QPACK::_read_insert_with_name_ref (lines 1515 and 1522, where a failed value decode still advances read_len by a negative ret and stores an unset length).

```
922: uint64_t tmp;  // uninitialized
923: if ((ret = xpack_decode_integer(tmp, pos, pos + remain_len, 8)) < 0 && tmp > 0xFFFF) { return -1; }
926: pos += ret;   // ret can be -1 here
927: remain_len -= ret;   // remain_len underflows
...
287: if (ret < 0 && tmp > 0xFFFF) { return -1; }
1515: if ((ret = xpack_decode_integer(tmp, input, input + input_len, 6)) < 0 && tmp > 0xFFFF) { return -1; }
1522: if ((ret = xpack_decode_string(...)) < 0 && tmp > 0xFF) { return -1; }
```

**Fix:** Change every `< 0 && ... > LIMIT` to `< 0 || ... > LIMIT`, and initialize tmp to 0 at line 922. Also guard the loop against advancing when ret <= 0.

**Verification:** The `if ((ret = xpack_decode_integer/string(...)) < 0 && tmp > LIMIT)` idiom is genuinely inverted: xpack_decode_integer (src/proxy/hdrs/XPACK.cc:64-98) returns -1 on failure but pre-sets dst to the small partial value (line 72), so on the common truncated-integer failure `tmp` is small and `ret<0 && tmp>LIMIT` is false, skipping the error return. I traced a directly attacker-reachable exploitation with no setup required: QPACK::_on_encoder_stream_read_ready (QPACK.cc:1136-1150) parses raw bytes from the client-controlled QPACK encoder stream and calls _read_insert_with_name_ref. A single malformed instruction byte 0xBF makes xpack_decode_integer at line 1515 return -1 with tmp=63; the inverted check does not return; line 1519 `read_len += ret` underflows read_len to SIZE_MAX; line 1522 computes buf_start = input + SIZE_MAX = input-1, causing an out-of-bounds stack read at XPACK.cc:113; on the ensuing string-decode failure tmp is left unset so the second inverted check (line 1522, tmp>0xFF) is also skipped, leaving `value` (declared uninitialized at line 1148) used and str_free'd at lines 1157-1158, and reader.consume() called with ~SIZE_MAX at line 1529. The _decode_header prefix path (lines 923/926) similarly advances pos by a negative ret producing OOB reads before the buffer (lines 932/936/953). No length/well-formedness validation guards these decodes (Http3HeaderVIOAdaptor.cc:63 passes the raw frame length; line 1140 peeks bytes without validation), and no mutex/lifetime invariant is relevant to this pure parsing defect.

**Verifier correction:** Two mechanism details in the claim are slightly off, though the conclusion holds. (1) In _decode_header, `remain_len -= ret` with ret=-1 increments remain_len by 1 rather than underflowing to a huge size_t; the OOB there stems from `pos += ret` moving pos before the buffer. The genuine size_t underflow is in _read_insert_with_name_ref's `read_len += ret` (line 1519). (2) The second _decode_header site at line 932 uses `< 0xFFFF` (not `> 0xFFFF`), and because a truncated 7-bit integer only fails after reaching >=127, that specific check actually does return on the common failure and is largely non-exploitable. The truly vulnerable sites are lines 923, 287, 1515, and 1522.

#### [LOW] HTTP/2 DATA padding length off-by-one allows pad_length == payload_length (unsigned underflow in data accounting)
**`src/proxy/http2/Http2ConnectionState.cc:159`** · _logic-bug_

For a padded DATA frame the pad-length byte occupies one octet of the payload, so valid padding must satisfy pad_length <= payload_length - 1; RFC 9113 6.1 requires a connection error when the padding length is >= the frame payload. The check uses `pad_length > payload_length`, which admits pad_length == payload_length. In that case nbytes == 1 and stream->increment_data_length(payload_length - pad_length - nbytes) evaluates the unsigned expression 0u - 1u == 0xFFFFFFFF, inflating the stream's tracked data_length by ~4 GiB. unpadded_length becomes 0 so no OOB write occurs, but the corrupted data_length makes the subsequent Content-Length validation (payload_length_is_valid, content_length != data_length) spuriously fail, turning the transaction into a stream PROTOCOL_ERROR. Impact is limited to the offending stream, hence low severity, but it is an incorrect frame-validation boundary.

```
156: if (frame.header().flags & HTTP2_FLAGS_DATA_PADDED) {
157:   frame.reader()->memcpy(&pad_length, HTTP2_DATA_PADLEN_LEN, nbytes);
158:   nbytes += HTTP2_DATA_PADLEN_LEN;
159:   if (pad_length > payload_length) { // should be >= (or pad_length + HTTP2_DATA_PADLEN_LEN > payload_length)
...
168: stream->increment_data_length(payload_length - pad_length - nbytes);
```

**Fix:** Reject when pad_length + HTTP2_DATA_PADLEN_LEN > payload_length (i.e. treat pad_length >= payload_length as a PROTOCOL_ERROR), matching RFC 9113 6.1.


### Security Hardening (defensive)

_The config parsers (ip_allow ACL, SNI/cert lookup, remap regex substitution), Content-Length validation, PROXY-protocol v2 parsing, and the chunked decoder are generally well-guarded with explicit overflow/bounds checks. The strongest issues are in wire-facing binary header decoders: QPACK (HTTP/3) mishandles decode errors on the header-data-prefix by AND-ing an error return with an unrelated range check, producing a negative-offset pointer advance and out-of-bounds reads on attacker-controlled input; and the HTTP/2 DATA-frame padding check is off-by-one (uses `>` instead of `>=`), permitting an integer underflow in per-stream data-length accounting. Both are reachable directly from untrusted client frames when the respective protocol is enabled._

#### [HIGH ✓verified] QPACK header-data-prefix decode ignores integer-decode errors, causing negative pointer advance and out-of-bounds reads
**`src/proxy/http3/QPACK.cc:923`** · _memory-bug_

In QPACK::_decode_header the error check for xpack_decode_integer combines the error return with an unrelated bound using logical AND: `if ((ret = xpack_decode_integer(tmp, pos, pos + remain_len, 8)) < 0 && tmp > 0xFFFF) { return -1; }`. xpack_decode_integer returns XPACK_ERROR_COMPRESSION_ERROR (== -1) on a decode failure (e.g. an over-long HPACK/QPACK integer: the m>=64 path in src/proxy/hdrs/XPACK.cc:81). Because the guard only returns when BOTH ret<0 AND tmp>0xFFFF, an attacker can trigger a decode error while keeping tmp<=0xFFFF (send prefix byte 0xFF followed by eleven 0x80 continuation bytes, which keeps the accumulator at 255 while forcing the m>=64 error). Execution then falls through to `pos += ret;` (pos moves to header_block-1) and `remain_len -= ret;` (remain_len grows), after which `pos[0]` (line 936) and the following decode loop read one byte before the buffer and parse from shifted offsets. The identical mistake appears at line 932 for delta_base_index (`... < 0 && delta_base_index < 0xFFFF`). Additionally `uint64_t tmp;` (line 922) is uninitialized, so the tmp>0xFFFF test reads an indeterminate value on the empty-buffer error path, and the intended 16-bit range validation of largest_reference is entirely dead (when ret>0 the first clause is false, so tmp>0xFFFF is never acted on and `uint16_t largest_reference = tmp` truncates silently). Reachable on the HTTP/3 request path via a crafted encoded field section.

```
922:  uint64_t tmp;
923:  if ((ret = xpack_decode_integer(tmp, pos, pos + remain_len, 8)) < 0 && tmp > 0xFFFF) {
924:    return -1;
925:  }
926:  pos                        += ret;
927:  remain_len                 -= ret;
928:  uint16_t largest_reference  = tmp;
... 
932:  if ((ret = xpack_decode_integer(delta_base_index, pos, pos + remain_len, 7)) < 0 && delta_base_index < 0xFFFF) {
933:    return -2;
934:  }
```

**Fix:** Separate the error check from the range check: return the error whenever ret < 0 (before touching pos/remain_len), then validate tmp/delta_base_index ranges independently. Initialize tmp to 0. Apply the same fix to the delta_base_index decode at line 932.

**Verification:** Traced the full failure end-to-end. src/proxy/http3/QPACK.cc:923 uses `(ret = xpack_decode_integer(...)) < 0 && tmp > 0xFFFF`; the `&&` makes a decode error actionable only when tmp is also >0xFFFF. xpack_decode_integer (src/proxy/hdrs/XPACK.cc:81-84) returns XPACK_ERROR_COMPRESSION_ERROR (-1, include/proxy/hdrs/XPACK.h:30) on the m>=64 over-long-integer path WITHOUT clearing dst. Attacker sends prefix 0xFF (n=8 -> dst=255=(1<<8)-1, enters continuation loop) followed by eleven 0x80 bytes: each added_value = 0x80&0x7f = 0 so dst stays 255, and *p&0x80 keeps the loop alive until m reaches 70 (>=64) -> returns -1 with tmp==255. Guard's second clause (255>0xFFFF) is false, so no early return. Then pos += ret (-1) sets pos = header_block-1 (line 926) and remain_len -= ret grows it (line 927). Line 932's second xpack_decode_integer(..., pos, pos+remain_len, 7) dereferences *(header_block-1), and line 936 pos[0] reads header_block[-1]. The buffer is a plain ats_malloc allocation (src/proxy/http3/Http3Frame.cc:350), making this a one-byte-before-heap OOB read, after which the instruction loop parses from shifted offsets. Reachable via Http3HeaderVIOAdaptor::handle_frame (Http3HeaderVIOAdaptor.cc:63) -> QPACK::decode -> _decode -> _decode_header on an attacker-controlled HEADERS frame; decode() at line 287 carries the same inverted guard, forcing largest_reference=255 into the blocked list, and _resume_decode later re-runs _decode_header where the OOB fires. Line 922 `uint64_t tmp;` is also uninitialized, so the empty-buffer error path (xpack_decode_integer returns -1 before setting dst) reads an indeterminate tmp. No mutex, bounds check, or upstream validation guards these reads; this is a parsing/pointer-arithmetic defect, not a continuation-lifetime race, so event-dispatch mutex protection is irrelevant. Found no guard refuting the claim.

#### [MEDIUM] HTTP/2 DATA frame padding length check off-by-one allows integer underflow in stream data-length accounting
**`src/proxy/http2/Http2ConnectionState.cc:159`** · _overflow_

rcv_data_frame validates the DATA pad length with `if (pad_length > payload_length)`, but the frame payload also contains the 1-byte pad-length field (HTTP2_DATA_PADLEN_LEN, nbytes becomes 1). The correct invariant is pad_length + 1 <= payload_length, i.e. the frame must be rejected when pad_length >= payload_length. The equal case (pad_length == payload_length) is wrongly accepted. Line 168 then computes `stream->increment_data_length(payload_length - pad_length - nbytes)`; with pad_length == payload_length and nbytes == 1 this is `payload_length - payload_length - 1`, which underflows in unsigned 32-bit arithmetic to 0xFFFFFFFF and is added to the uint64_t data_length. When the request carries no Content-Length, payload_length_is_valid() (Http2Stream.h:429) skips the mismatch check, so the corrupted ~4GB data_length propagates into read_vio.nbytes (Http2Stream.cc:380), making the state machine expect a multi-gigabyte body that never arrives (stream stall / resource consumption). The sibling HEADERS path at line 396 uses the correct form `(params.pad_length + HTTP2_HEADERS_PADLEN_LEN) > header_block_fragment_length`, confirming the DATA check is the inconsistent one. Reachable with any DATA frame of payload_length in [1,255], PADDED flag set, pad-length byte equal to payload_length.

```
156:  if (frame.header().flags & HTTP2_FLAGS_DATA_PADDED) {
157:    frame.reader()->memcpy(&pad_length, HTTP2_DATA_PADLEN_LEN, nbytes);
158:    nbytes += HTTP2_DATA_PADLEN_LEN;
159:    if (pad_length > payload_length) {
...
165:    }
166:  }
168:  stream->increment_data_length(payload_length - pad_length - nbytes);
```

**Fix:** Reject when the padding plus the pad-length octet do not fit: `if (pad_length + HTTP2_DATA_PADLEN_LEN > payload_length)` (mirroring the HEADERS path), so pad_length == payload_length is treated as a PROTOCOL_ERROR and the subtraction can never underflow.

#### [LOW] HTTP/2 and HTTP/3 total-header-size limit relaxation overflows when max_header_list_size doubled
**`src/proxy/http2/Http2ConnectionState.cc:450`** · _overflow_

The buffered header-block cap is computed as `std::max(Http2::max_header_list_size, Http2::max_header_list_size * 2)` (also at line 1106). max_header_list_size is uint32_t and defaults to 4294967295 (HTTP2.cc:473); the `* 2` overflows uint32_t and wraps to a smaller value, so std::max silently falls back to the un-doubled value and the intended 'relax to double' behavior never takes effect for large configured limits. This is not itself exploitable (std::max keeps the effective cap at least at the configured value, and hpack_decode_header_block strictly bounds the decoded size), but the computation is misleading and the doubling intent is silently lost; the HTTP/3 side has the same UINT32_MAX default (Http3.cc:29 HTTP3_DEFAULT_MAX_FIELD_SECTION_SIZE) where the effective per-stream buffered-size cap is likewise unbounded by default. Worth tightening so the buffered-bytes ceiling is computed in 64-bit and the default is a real finite limit.

```
449:  // The total "decoded" header length is strictly checked by hpack_decode_header_block().
450:  if (stream->header_blocks_length > std::max(Http2::max_header_list_size, Http2::max_header_list_size * 2)) {
451:    return Http2Error(Http2ErrorClass::HTTP2_ERROR_CLASS_CONNECTION, Http2ErrorCode::HTTP2_ERROR_ENHANCE_YOUR_CALM,
452:                      "header blocks too large");
```

**Fix:** Compute the doubled ceiling in uint64_t (e.g. `static_cast<uint64_t>(Http2::max_header_list_size) * 2`) and compare against the 64-bit value, or clamp; consider a finite default for max_header_list_size / max_field_section_size instead of the max-integer sentinel.


### Cache (disk, RAM, directory, aggregation)

_The src/iocore/cache tree in this checkout is byte-for-byte identical to upstream ATS master, so these are genuine latent issues in shipping code rather than injected bugs. The most consequential is that Doc::len read from disk is trusted throughout the read path (checksum verification, RAM-cache insertion, IOBufferBlock construction) without ever being bounded against the actual read-buffer size, so a corrupted Doc that retains DOC_MAGIC drives out-of-bounds reads. Secondary concerns are a cross-thread data race where readers inspect writer CacheVC scalar state under only the stripe lock, an on-disk directory-load path that trusts structure the shm fast-restart path fully validates, and a self-documented 'temporary fix' masking a fragment-offset correctness bug. No definitive use-after-free or stripe-lock leak was confirmed in the cancel/abort or aggregation paths; the recursive-read UAF that the test hooks in CacheRead.cc target appears already mitigated by the thread_local recursion counter._

#### [MEDIUM] Doc::len read from disk is trusted as the object length without bounding to the read buffer, enabling out-of-bounds reads
**`src/iocore/cache/CacheVC.cc:406`** · _memory-bug_

In handleReadDone the read buffer is allocated to dir_approx_size(&dir) (via do_read_call setting io.aiocb.aio_nbytes, then handleRead allocating buf = new_IOBufferData(iobuffer_size_to_index(io.aiocb.aio_nbytes,...)) at CacheVC.cc:521). After the read, the only integrity gates are stripe->dir_valid(&dir), doc->magic == DOC_MAGIC, and the version check. Nothing validates that doc->len (a value taken verbatim from the on-disk Doc) is <= the allocated buffer. The checksum loop then walks `b < (char*)doc + doc->len` and the RAM-cache insertion (stripe->ram_cache->put(read_key, buf.get(), doc->len, ...) at CacheVC.cc:442, which memcpys doc->len bytes when copy/compress is enabled) both dereference up to doc->len bytes. The same unbounded trust reappears in openReadMain (bytes = doc->len - doc_pos; new_IOBufferBlock(buf, bytes, doc_pos) at CacheRead.cc:567/697), which would hand out-of-bounds bytes to the client read buffer. A corrupted/torn Doc whose 4-byte magic still equals DOC_MAGIC (e.g. from a partial aggregation write or an adjacent object bleed) produces an over-large len and drives an OOB read. dir_approx_size only bounds the fragment's rounded size, not doc->len.

```
for (char *b = doc->hdr(); b < reinterpret_cast<char *>(doc) + doc->len; b++) {
  checksum += *b;
}   // CacheVC.cc:406-408, buf sized to io.aiocb.aio_nbytes = dir_approx_size(&dir)
```

**Fix:** After confirming DOC_MAGIC, validate doc->len against io.aiocb.aio_nbytes (and against sizeof(Doc)+doc->hlen for the header) before running the checksum loop, ram_cache->put, or building IOBufferBlocks; treat an out-of-range len as DOC_CORRUPT and remove the dir entry, as is already done for other corruption cases.

#### [MEDIUM] Reader inspects writer CacheVC state (closed/fragment/start_time/alternate_index) across threads holding only the stripe lock
**`src/iocore/cache/CacheRead.cc:276`** · _race_

During read-while-writer, openReadChooseWriter and openReadFromWriter read fields of the writer CacheVC (write_vc->closed at CacheRead.cc:276 and :285, write_vc->fragment at :285, and in openReadChooseWriter w->start_time, w->closed, w->alternate_index, w->alternate.valid() at :118 and :134-165) while holding only stripe->mutex. The writer's own state transitions are not all serialized by the stripe lock: CacheVC::do_io_close sets `closed` under the writer's own mutex (CacheVC.cc:233-243, ink_assert(mutex->thread_holding == this_ethread())), which is the HttpSM mutex, not stripe->mutex. So a reader on one thread can read `closed`/`fragment` concurrently with the writer mutating them on another thread. The write_vc->mutex is only acquired later (CacheRead.cc:296). This is a data race on non-atomic ints; a stale/torn read of `closed` can make the reader treat an aborting writer as live (or vice versa) before the writer-lock section re-validates.

```
OpenDirEntry *cod = od;
od                = nullptr;
// someone is currently writing the document
if (write_vc->closed < 0) {   // CacheRead.cc:273-276, only stripe lock held; closed set under writer's own mutex in do_io_close
```

**Fix:** Only read writer-mutable scalar state after acquiring write_vc->mutex, or make the fields that are legitimately observed under the stripe lock (closed) atomic and document the invariant. At minimum audit which writer fields are stripe-lock-protected vs writer-mutex-protected and confine the pre-writer-lock reads to the former.

#### [LOW] On-disk directory is accepted on magic/version alone, without the structural validation the shm fast-restart path performs
**`src/iocore/cache/StripeSM.cc:269`** · _security-hardening_

handle_dir_read accepts a directory read from disk after checking only header/footer magic and major-version range (StripeSM.cc:269-280). It does not validate freelist heads or per-entry next/prev link bounds. In contrast, the shared-memory fast-restart attach path validates exactly these (Stripe::_shm_directory_is_valid / _shm_segment_membership_is_valid in Stripe.cc:184-314) precisely because 'CacheVC::handleRead() turns an out-of-stripe offset into a negative (so huge) read length' and 'the next insert to find that empty row writes through its stale prev/next into a live chain.' The disk path relies on recover_data() rescanning the tail, but a directory whose body is corrupted while header/footer magic+sync_serial remain consistent is trusted wholesale; freelist_pop/next_dir/dir_from_offset then index by unchecked 16-bit link values (CHECK_DIR is compiled out by default), allowing OOB segment traversal and directory corruption.

```
if (!(directory.header->magic == STRIPE_MAGIC && directory.footer->magic == STRIPE_MAGIC &&
      CACHE_DB_MAJOR_VERSION_COMPATIBLE <= directory.header->version._major &&
      directory.header->version._major <= CACHE_DB_MAJOR_VERSION)) {   // StripeSM.cc:269 - only gate before trusting whole dir
```

**Fix:** Run the same segment/freelist structural validation used for the shm path (or Directory::check()) on the disk-loaded directory before use, clearing the stripe on failure, so both restore paths share one trust gate.

#### [LOW] scanObject/openReadMain fragment-table seek carries an unresolved 'temporary fix' that corrupts objects on bad frag offsets
**`src/iocore/cache/CacheRead.cc:650`** · _logic-bug_

openReadMain's pread/seek path computes doc_pos from the alternate fragment table and, when the resulting bytes goes negative for an HTTP asset, the code itself documents that the root cause is unknown ('It must be the case that either the fragment offsets are incorrect or a fragment table isn't being created when it should be') and reacts by marking the live doc DOC_CORRUPT and removing the directory entry (CacheRead.cc:650-683). This is a self-acknowledged band-aid on a fragment-offset/fragment-table correctness bug: legitimate range requests against affected multi-fragment objects evict otherwise-valid cache entries and fail the read. Worth a maintainer's attention because the underlying fragment-offset accounting (push_frag_offset in openWriteWriteDone/openWriteCloseDataDone and the seek math here) is the real defect, not the cleanup.

```
// This shouldn't happen for HTTP assets but it does
// occasionally in production. This is a temporary fix
// to clean up broken objects until the root cause can
// be found. ... if (frag_type == CACHE_FRAG_TYPE_HTTP && bytes < 0) { ... doc->magic = DOC_CORRUPT; ... }  // CacheRead.cc:644-683
```

**Fix:** Instrument the write-side frag offset table population (push_frag_offset paths) and the seek target selection to capture a reproducer, then fix the offset accounting so the negative-bytes case cannot arise, rather than silently evicting.


### Concurrency & Locking Discipline

_Locking discipline in the sampled iocore/proxy code is mostly sound: nearly all MUTEX_TRY_LOCK miss paths correctly reschedule (Transform, Http2Stream, UnixNetVConnection, NetAccept, InkAPI reenable paths), metrics are atomic, and the ProtectedQueue signal design is intentionally bounded-latency. The real problems cluster in HostDB's pending-DNS queue handoff — a timeout-vs-completion race that can deliver a second EVENT_HOST_DB_LOOKUP into a state machine that already consumed the first (crash grade), plus a leak of cancelled waiters — and in ConnectionTracker, where the non-atomic obtain/reserve sequence races release-time table erase and splits per-origin connection counting, weakening max-connection enforcement. Lesser issues: PluginVC's timeout setters mutate shared Event pointers with no lock (reachable from plugin threads via TSVConn*TimeoutSet), and the session-pool try-lock miss paths silently discard work (purge_keepalives no-ops under the exact contention it exists to relieve; acquire/release contention opens new origin connections or closes reusable ones, both marked FIX in comments)._

#### [HIGH ✓verified] HostDB pending-DNS waiter can call back its continuation twice (timeout vs. DNS-completion race)
**`src/iocore/hostdb/HostDB.cc:815`** · _race_

A HostDBContinuation queued behind an in-flight DNS query (handler dnsPendingEvent, its own mutex per init() at HostDB.cc:368) races with the owning continuation's remove_and_trigger_pending_dns() (HostDB.cc:1146-1186), which runs under only the refcountcache bucket lock. Sequence: (1) the waiter's 30s lookup timeout (proxy.config.hostdb.lookup_timeout defaults to 30, HostDB.cc:1196-1198) fires dnsPendingEvent with EVENT_INTERVAL; it acquires action.mutex and calls action.continuation->handleEvent(EVENT_HOST_DB_LOOKUP, nullptr). (2) Concurrently the DNS owner completes and remove_and_trigger_pending_dns() removes the waiter from the pending queue under the bucket lock and enqueues it on the local qq (the c->action.cancelled check at line 1161 is false — the action was completed, not cancelled). (3) The waiter's remove_from_pending_dns_for_hash() now returns false, so it neither frees itself nor clears `action` (unlike dnsEvent, which does `action = nullptr` at line 870), and returns EVENT_DONE. (4) The owner then locks c->mutex (line 1176) and re-invokes/schedules the waiter, whose handler path (dnsPendingEvent else-branch, lines 822-825) switches to probeEvent, re-acquires action.mutex, finds action.cancelled false, and delivers a second EVENT_HOST_DB_LOOKUP callback into a state machine that already consumed the first (failure) callback. HttpSM does not expect a second hostdb event after completing the lookup, so this is state corruption / crash grade on the production request path, though the timing window (timeout coinciding with DNS completion) is narrow.

```
src/iocore/hostdb/HostDB.cc:810-821:
    MUTEX_TRY_LOCK(lock, action.mutex, ((Event *)e)->ethread);
    ...
    if (!action.cancelled && action.continuation) {
      action.continuation->handleEvent(EVENT_HOST_DB_LOOKUP, nullptr);
    }
    if (hostDB.remove_from_pending_dns_for_hash(hash.hash, this)) {
      hostdb_cont_free(this);
    }
    return EVENT_DONE;
Note: no `action = nullptr` and no cleanup when remove_from_pending_dns_for_hash() returns false; remove_and_trigger_pending_dns() (lines 1154-1184) has already taken ownership and will re-invoke this continuation.
```

**Fix:** In dnsPendingEvent's timeout branch, treat delivery of the user callback and dequeue as one atomic step: hold the bucket lock while checking/removing queue membership before calling back, and only call back if the removal succeeded; if removal failed (owner already dequeued us), skip the callback and let the trigger path deliver the result. At minimum, set `action = nullptr` after the timeout callback and make the re-invoked probeEvent path bail out when action is empty.

**Verification:** Traced end-to-end; every load-bearing element of the claim checks out and no guard exists. (1) Setup: a waiter HostDBContinuation gets its own mutex (HostDB.cc:368) and, when another query for the same hash is in flight, set_check_pending_dns() returns false and the handler becomes dnsPendingEvent (HostDB.cc:1220-1222), with a 30s timeout scheduled (HostDB.cc:1196-1198; proxy.config.hostdb.lookup_timeout default "30" per src/records/RecordsConfig.cc:999). (2) The two contenders use DIFFERENT locks: the waiter's timeout handler runs under c->mutex (acquired by EThread::process_event at dispatch), while the owner's remove_and_trigger_pending_dns() removes the waiter from the pending queue under only the refcountcache bucket lock (HostDB.cc:1150-1154) and only later takes c->mutex (SCOPED_MUTEX_LOCK at 1176). Crucially, dnsPendingEvent delivers the failure callback (line 816) BEFORE removing itself from the queue (line 818), and holds neither the bucket lock nor any completion flag during the callback. Interleaving: waiter delivers EVENT_HOST_DB_LOOKUP(nullptr) at 816; concurrently owner's dnsEvent completes (calls remove_and_trigger_pending_dns at 1043), removes the waiter from q into qq under the bucket lock (action.cancelled is false at 1161 — the action was completed, not cancelled: HttpSM::state_hostdb_lookup just does pending_action = nullptr, src/proxy/http/HttpSM.cc:2516-2520, and never calls cancel on a completed action); waiter's remove_from_pending_dns_for_hash (HostDB.cc:231-241) then returns false, so it neither frees itself nor clears action (contrast dnsEvent's `action = nullptr` at 870) and returns EVENT_DONE; owner then passes the checks at 1170 (cancelled false, mutex non-null), acquires c->mutex, and re-invokes/schedules the waiter (1176-1183). The re-invocation hits dnsPendingEvent's else-branch (822-825) -> probeEvent (1059), where action.cancelled is still false and action.continuation still points at the SM, so it delivers a second callback (reply_to_cont at 1104-1106 if the owner's DNS result is now in cache, or the EVENT_HOST_DB_LOOKUP at 1089, or restarts do_dns). The SM has left state_hostdb_lookup, so the second event hits an arbitrary handler (asserts/corruption); worse, if the SM has since been freed (its pending_action was already nulled at HttpSM.cc:2517, so kill_this cancels nothing pointing at this waiter), probeEvent's `action.continuation->mutex` read at 1085 and the handleEvent are use-after-free — action.mutex (a Ptr<ProxyMutex>) keeps the mutex alive but not the HttpSM. Refutation attempts that failed: (a) c->mutex serialization only orders the two handlers, it does not prevent the sequential double delivery; (b) if the owner wins c->mutex first, probeEvent/the qq loop cancels the pending timeout (1064-1067, 1180-1182) and only one callback occurs — but that only shows the race requires the timeout dispatch to win c->mutex while the owner wins the bucket lock, exactly the claimed window; (c) same-thread execution makes the interleaving impossible, but owner (dnsEvent, often on a different ET_NET/ET_DNS thread) and waiter routinely live on different threads; (d) no completion flag, no `action = nullptr`, and no queue-membership re-check guards the re-invocation path — grep confirms dnsPendingEvent's timeout branch is the only callback site that neither frees nor nulls action afterward. The code deliberately avoids double-FREE via the remove_from_pending_dns_for_hash ownership handshake but has no equivalent protection against double-CALLBACK. Window is narrow (DNS must complete during the waiter's timeout callback execution, i.e., timeout ~coincides with completion) but real on the production path.

#### [MEDIUM] remove_and_trigger_pending_dns leaks HostDBContinuations whose action was cancelled
**`src/iocore/hostdb/HostDB.cc:1161`** · _memory-bug_

When the DNS owner wakes queued waiters, remove_and_trigger_pending_dns() removes every same-hash waiter from the pending queue (q.remove(c), line 1160) but only enqueues non-cancelled ones for re-dispatch (`if (!c->action.cancelled) qq.enqueue(c);` line 1161; also the `continue` at line 1170). A cancelled waiter (e.g. HttpSM cancelled its pending hostdb Action because the client aborted — a routine event under load) is silently dropped with no free. The only path that frees a cancelled waiter is dnsPendingEvent's timeout branch, which frees only when remove_from_pending_dns_for_hash() returns true (line 818-820) — but the waiter was already removed from the queue here, so that returns false and the continuation is never freed. If proxy.config.hostdb.lookup_timeout is 0 there is no timeout event at all and the leak is immediate. Its per-waiter timeout event (not cancelled here — only qq members get their timeout cancelled at lines 1180-1183) later fires into the leaked-but-live object, so this is a steady memory leak of HostDBContinuation objects proportional to client aborts during DNS query deduplication.

```
src/iocore/hostdb/HostDB.cc:1156-1171:
      if (hash.hash == c->hash.hash) {
        Dbg(dbg_ctl_hostdb, "dequeuing additional request");
        q.remove(c);
        if (!c->action.cancelled) {
          qq.enqueue(c);
        }
      }
      ...
  while ((c = qq.dequeue())) {
    if (c->action.cancelled || c->mutex == nullptr) {
      continue;
    }
Neither drop path frees `c` or cancels its pending `timeout` event; hostdb_cont_free is never reached for these continuations.
```

**Fix:** When a cancelled waiter is removed from the pending queue (both the line 1161 skip and the line 1170 continue), take its mutex, cancel its `timeout` event, and call hostdb_cont_free(c) instead of dropping the pointer.

#### [MEDIUM] ConnectionTracker group obtain/reserve is not atomic against release-time erase, splitting per-origin connection counting
**`src/iocore/net/ConnectionTracker.cc:531`** · _race_

Group::release() decrements the atomic _count and, when it hits 0, takes the table mutex, rechecks `_count > 0`, and erases the group from the table (lines 526-539). But a transaction acquires a group in two non-atomic steps: obtain_outbound() copies the shared_ptr under the table lock (ConnectionTracker.cc:419-429, invoked from HttpSM.cc:5895-5897) and only later increments _count via TxnState::reserve() (ConnectionTracker.h:448-459, invoked at HttpSM.cc:5903/5924) with no lock spanning the two. Window: T1 obtains the group while another connection holds _count==1; that connection releases, sees count 0, takes the table lock (T1 released it already), sees `_count > 0` false, and erases the group. T1 then reserves on the now-orphaned group while any subsequent transaction creates a brand-new Group for the same key with _count starting at 0. Two groups now count the same origin independently, so proxy.config.http.per_server.connection.max can be exceeded (up to ~2x transiently) and the per-server metrics (gauge mirrors) diverge. Memory safety is preserved by shared_ptr; only the limit enforcement and accounting are wrong.

```
src/iocore/net/ConnectionTracker.cc:526-539:
  if (_count > 0) {
    auto count = --_count;
    ...
    if (count == 0) {
      TableSingleton             &table = ...;
      std::lock_guard<std::mutex> lock(table._mutex); // Table lock
      if (_count > 0) {
        // Someone else grabbed the Group between our last check and taking the lock.
        return;
      }
      table._table.erase(_key);
    }
and include/iocore/net/ConnectionTracker.h:449-453 (reserve increments _count with no table lock, after obtain_outbound released it).
```

**Fix:** Make obtain_* perform the initial reservation (increment _count) while still holding the table mutex, or have release() erase only groups whose shared_ptr use_count shows no outstanding TxnState holders (e.g. check `loc->second.use_count() == 1` under the table lock) so a group referenced by a not-yet-reserved TxnState is never removed.

#### [MEDIUM] PluginVC timeout setters mutate active_event/inactive_event without holding the PluginVC mutex
**`src/proxy/PluginVC.cc:826`** · _race_

PluginVC::set_inactivity_timeout (lines 825-841) and set_active_timeout (lines 807-823) cancel and reschedule the shared Event pointers inactive_event/active_event with no lock, unlike every other mutator in this file (do_io_close takes SCOPED_MUTEX_LOCK at line 383, reenable at line 325). These setters are reachable from arbitrary plugin threads via TSVConnActiveTimeoutSet/TSVConnInactivityTimeoutSet (src/api/InkAPI.cc:6161-6185), which take no lock either — e.g. right after TSHttpConnect returns the active PluginVC, before any do_io establishes a shared mutex. Meanwhile main_handler concurrently reads and reschedules these events: the lock-retry paths at lines 149-151, 159-161, 173-175, 186-188 compare `call_event != inactive_event` and call call_event->schedule_in() holding only the core mutex — and those retry paths execute precisely when another thread holds the VIO mutex, which is exactly when an SM can be inside set_inactivity_timeout cancelling and nulling the same event. Event::cancel() from a thread that does not hold the continuation's mutex also violates the event-system contract, racing the owning EThread's cancelled-check-then-free of the periodic inactive_event. Result: unsynchronized cancel/schedule on the same Event object with a narrow use-after-free window on the periodic event, plus torn reads of the event pointers.

```
src/proxy/PluginVC.cc:825-841 (no lock acquired):
  PluginVC::set_inactivity_timeout(ink_hrtime timeout_in)
  {
    inactive_timeout = timeout_in;
    if (inactive_timeout != 0) {
      inactive_timeout_at = ink_get_hrtime() + inactive_timeout;
      if (inactive_event == nullptr) {
        inactive_event = eventProcessor.schedule_every(this, HRTIME_SECONDS(1));
      }
    } else {
      inactive_timeout_at = 0;
      if (inactive_event) {
        inactive_event->cancel();
        inactive_event = nullptr;
      }
    }
contrast with main_handler's unlocked-side read at lines 149-151:
      if (call_event != inactive_event) {
        call_event->schedule_in(PVC_LOCK_RETRY_TIME);
      }
```

**Fix:** Take SCOPED_MUTEX_LOCK(lock, mutex, this_ethread()) in set_active_timeout/set_inactivity_timeout (matching do_io_close), or convert PluginVC timeouts to the deadline-timestamp style UnixNetVConnection uses (plain int fields checked by the handler) so no Event objects are cancelled/scheduled cross-thread.

#### [LOW] purge_keepalives silently no-ops on pool lock contention and never purges thread-local pools
**`src/proxy/http/HttpSessionManager.cc:373`** · _logic-bug_

HttpSessionManager::purge_keepalives() is the emergency relief valve invoked when the global proxy.config.http.server_max_connections limit is hit (HttpSM.cc:5878-5880). It uses MUTEX_TRY_LOCK on the global pool mutex and, on a miss, does nothing — no retry, no reschedule — with the miss path literally commented as an open question. Under exactly the conditions where this is called (connection pressure, hence heavy pool traffic and lock contention), the purge is most likely to be silently dropped, and the transaction is failed with ENFILE while keep-alive origin sessions that could have been reaped stay open. It also only purges m_g_pool, never the per-thread pools (acknowledged by the TODO above the function), so in THREAD/HYBRID sharing modes most pooled sessions are untouched.

```
src/proxy/http/HttpSessionManager.cc:369-377:
void
HttpSessionManager::purge_keepalives()
{
  EThread *ethread = this_ethread();

  MUTEX_TRY_LOCK(lock, m_g_pool->mutex, ethread);
  if (lock.is_locked()) {
    m_g_pool->purge();
  } // should we do something clever if we don't get the lock?
}
```

**Fix:** On lock miss, schedule a continuation to retry the purge (the caller has already failed the current transaction, so the purge just needs to happen soon, not synchronously), and schedule per-thread purge events on each ET_NET thread so thread-local pools are also drained.

#### [LOW] Session pool try-lock contention silently discards reuse: new origin connections opened and healthy sessions closed
**`src/proxy/http/HttpSM.cc:5801`** · _performance_

Both directions of shared-pool access degrade permanently on a single MUTEX_TRY_LOCK miss instead of retrying. Acquire: HttpSessionManager::_acquire_session returns HSMresult_t::RETRY when the global pool try-lock misses (HttpSessionManager.cc:523-525), and HttpSM treats RETRY as a miss and proceeds to open a brand-new origin connection (the code itself says the lock should be retried). Release: Http1ServerSession::release_transaction -> httpSessionManager.release_session returns RETRY on contention (HttpSessionManager.cc:576-581) and the caller closes a perfectly reusable keep-alive origin connection (Http1ServerSession.cc:230-235, counted in origin_shutdown_pool_lock_contention). With the GLOBAL sharing pool on a many-core box, this converts transient lock contention into extra origin connection churn — measurable via the origin_reuse_fail and origin_shutdown_pool_lock_contention metrics. GLOBAL_LOCKED exists as a blocking-lock workaround, which confirms the contention path is real in practice.

```
src/proxy/http/HttpSM.cc:5801-5805:
    case HSMresult_t::RETRY:
      Metrics::Counter::increment(http_rsb.origin_reuse_fail);
      //  Could not get shared pool lock
      //   FIX: should retry lock
      break;
and src/proxy/http/Http1ServerSession.cc:230-235:
    if (r == HSMresult_t::RETRY) {
      // Session could not be put in the session manager
      //  due to lock contention
      // FIX:  should retry instead of closing
      do_io_close(HTTP_ERRNO);
      Metrics::Counter::increment(http_rsb.origin_shutdown_pool_lock_contention);
```

**Fix:** Implement the FIX comments: on RETRY, schedule a short (e.g. HRTIME_MSECONDS(10)) retry event for the pool operation (bounded to a couple of attempts) before falling back to opening a new connection or closing the session, mirroring the retry pattern already used throughout the codebase for MUTEX_TRY_LOCK misses.


### HTTP/1.x State Machine (HttpSM / HttpTransact)

_The HTTP/1.x proxy state machine is mature and its obvious teardown hazards (reentrancy-gated kill_this, guarded double do_io_close on Http1/Http2 sessions, vc_table clearing) are handled deliberately. I did not find a confirmable critical use-after-free or double-free on the hot request/response paths. The issues found are latent/edge-case defects: an unconditional _ua.get_txn() dereference in server response header parsing that contradicts a null-guard in the same function (SCHEDULED_UPDATE/REVPROXY), a server_entry null-deref assumption in the default tunnel_handler for cache-only responses, and a state-machine concern in the config-gated attach_server_session_to_client path where the origin transaction is still closed via kill_this after the session was handed to the client. Severities are conservative because the strongest candidates are gated behind rare configs or request flavors and could not be executed to confirm the fault._

#### [MEDIUM] Unconditional _ua.get_txn() dereference in server response header parse (null for SCHEDULED_UPDATE/REVPROXY)
**`src/proxy/http/HttpSM.cc:2211`** · _logic-bug_

In state_read_server_response_header(), the ParseResult::DONE branch unconditionally does `_ua.get_txn()->set_inactivity_timeout(...)`. The very same function guards this pointer earlier (line 2106: `if (_ua.get_txn() && _ua.get_txn()->has_request_body(...))`), and setup_server_read_response_header() — which installs this handler — explicitly asserts that `_ua.get_txn()` may be null for HttpRequestFlavor_t::SCHEDULED_UPDATE / REVPROXY (line 7096-7097). Reaching DONE on such a flavor dereferences a null user-agent transaction. This is an internal-request/scheduled-update path, so exposure is limited, but the guard inconsistency within one function makes it a real latent null-deref.

```
line 2106: `if (_ua.get_txn() && _ua.get_txn()->has_request_body(...))` (guarded)
line 2211: `_ua.get_txn()->set_inactivity_timeout(HRTIME_SECONDS(t_state.txn_conf->transaction_no_activity_timeout_in));` (unguarded)
setup_server_read_response_header assert (7096): `ink_assert(_ua.get_txn() != nullptr || t_state.req_flavor == HttpTransact::HttpRequestFlavor_t::SCHEDULED_UPDATE || t_state.req_flavor == HttpTransact::HttpRequestFlavor_t::REVPROXY);`
```

**Fix:** Guard the set_inactivity_timeout with `if (_ua.get_txn())`, matching the guard already present at line 2106 and the null-tolerance documented in setup_server_read_response_header().

#### [LOW] tunnel_handler dereferences server_entry without null check
**`src/proxy/http/HttpSM.cc:3279`** · _logic-bug_

HttpSM::tunnel_handler is installed as the SM default handler for tunnels that have no origin connection, e.g. a pure cache hit via setup_cache_read_transfer() (line 7159), where server_entry is null. Its first statement dereferences `server_entry->eos` when the event is a stray WRITE_READY/WRITE_COMPLETE. In the common flow only HTTP_TUNNEL_EVENT_DONE reaches this handler for serverless tunnels (body VIOs are owned by the HttpTunnel continuation, not the SM), so it is not currently reachable, but the code assumes server_entry is always present. Any future path that routes a write event to the SM default handler on a cache-only response would crash. The author's own comment ("a WRITE event appear after receiving EOS from the server connection") shows the check was written assuming a server side exists.

```
line 3279: `if ((event == VC_EVENT_WRITE_READY || event == VC_EVENT_WRITE_COMPLETE) && server_entry->eos) {`
setup_cache_read_transfer installs this as default handler (line 7159: `HTTP_SM_SET_DEFAULT_HANDLER(&HttpSM::tunnel_handler);`) with no server_entry.
```

**Fix:** Add a `server_entry &&` guard: `if ((event == VC_EVENT_WRITE_READY || event == VC_EVENT_WRITE_COMPLETE) && server_entry && server_entry->eos)`.

#### [LOW] Server transaction closed after being attached to client session (attach_server_session_to_client)
**`src/proxy/http/HttpSM.cc:3522`** · _logic-bug_

In tunnel_handler_server, when proxy.config.http.attach_server_session_to_client==1 and the client is keep-alive, the origin PoolableSession is handed to the client session via _ua.get_txn()->attach_server_session(...), which sets the session state to KA_RESERVED and issues a slave keep-alive read owned by the client session. However server_txn is not cleared here, so later in kill_this() (line 7967-7970) server_txn->transaction_done() runs, reaching Http1ServerSession::release_transaction. For a KA_RESERVED, non-private, sharing-enabled session that path is neither SSN_TO_RELEASE nor sharing_match==0, so it falls into the final else and calls do_io_close(HTTP_ERRNO) on the session that was just bound to the client — tearing down the netvc the client's slave_ka_vio is still reading. I could not execute this config-gated path to confirm the resulting dangling bound_ss, so severity is set conservatively; it warrants verification of the release_transaction state handling for KA_RESERVED.

```
tunnel_handler_server (3519-3524): `if (t_state.txn_conf->attach_server_session_to_client == 1 && _ua.get_txn() && ... ) { if (_ua.get_txn()->attach_server_session(static_cast<PoolableSession *>(server_txn->get_proxy_ssn()))) { release_origin_connection = false; } }` — server_txn left non-null.
Http1ServerSession::release_transaction else branch: `do_io_close(HTTP_ERRNO);`
Http1ClientSession::attach_server_session sets `ssession->state = PoolableSession::PooledState::KA_RESERVED;` and `slave_ka_vio = ssession->do_io_read(this, ...)`.
```

**Fix:** Verify release_transaction handles KA_RESERVED (a session already handed off to a client) without do_io_close, or clear server_txn / mark the session so transaction_done does not close a session still bound as a client slave.


### Header / URL Parsing

_The MIME/HTTP/URL parsers in src/proxy/hdrs are, on the whole, well-hardened against the classic request-smuggling vectors: whitespace-before-colon is rejected for requests (MIME.cc:2506), embedded CR/LF/CTL in field values is rejected (MIME.cc:2560-2565), Content-Length is validated with std::from_chars including overflow/negative rejection and duplicate-value comparison (HTTP.cc:1272-1300), TE-overrides-CL is applied, and the CryptoHash fast/general cache-key paths are kept consistent (host lowercased, path left un-decoded in both). The obs-fold split-buffer limitation is already documented in-code. The most substantive issue found is a latent stale-pointer/use-after-free hazard in the comma-value mutators, whose HeapGuard pins only the list head cell while several callers put off-heap data in that head slot. The remaining findings are lower-severity leniency/consistency issues in port and status-line parsing._

#### [MEDIUM] Comma-value mutators can leave list cells unprotected against heap coalescing (stale pointer / UAF)
**`src/proxy/hdrs/MIME.cc:1835`** · _use-after-free_

mime_field_value_str_from_strlist() protects the field's string heap from garbage-collection during its allocate_str() call with a single HeapGuard pinned to list->head->str, relying on the invariant stated in the comment at line 1834 that "all strings are from the same heap." Several callers violate that invariant by placing an off-heap pointer into the cell that becomes the list head, so the guard pins nothing while the remaining cells still point into the original (now unpinned) string heap. If allocate_str() at line 1851 triggers coalesce_str_heaps() (reachable when m_lost_string_space exceeds MAX_LOST_STR_SPACE, or when a demote fails because all ronly slots are occupied), the original rw/ronly heap can be evacuated and freed, leaving cells 1..n dangling; the memcpy(dest, cell->str, cell->len) at line 1861 then reads freed memory. Affected callers: mime_field_value_insert_comma_val() with idx==0 (list.prepend of a cell whose str is caller memory new_piece.data(), MIME.cc:1968-1979); mime_field_value_set_comma_val() when idx==0 sets head->str = new_piece.data() (MIME.cc:1889); mime_field_value_extend_comma_val() when idx==0 sets head->str = temp_ptr, a stack/ats_malloc buffer (MIME.cc:2045). These are reachable from plugins via the InkAPI TSMimeHdrFieldValue* entry points (e.g. InkAPI.cc:2403), with plugin-controlled idx>=0.

```
HdrHeap::HeapGuard guard(heap, list->head->str);  // MIME.cc:1835, comment: "This works, because all strings are from the same heap when it is split into the list."  ... new_value = heap->allocate_str(new_value_len); (1851) ... memcpy(dest, cell->str, cell->len); (1861). Caller extend sets: cell->str = temp_ptr; (2045). Caller insert prepends new_piece cell at head; caller set does cell->str = new_piece.data(); (1889).
```

**Fix:** Do not rely on head-cell-only pinning. Either build the reassembled value from a copy that is guaranteed heap-resident, guard every heap that any cell points into, or (simplest) construct the concatenated result in a temporary buffer first and only then call allocate_str + memcpy so no live cell pointer is read after a possible coalesce.

#### [LOW] URL port accepts trailing non-digit garbage, desyncing numeric port from stored port text
**`src/proxy/hdrs/URL.cc:479`** · _logic-bug_

URLImpl::set_port(std::string_view) parses digits until the first non-digit and simply break()s, but then unconditionally stores the ENTIRE original text (including the non-digit tail) as m_ptr_port/m_len_port at line 493. url_parse_internet() (URL.cc:1378) assigns the port field as everything from last_colon+1 up to cur, and cur only stops at '/', '?', '#', or end — non-digit bytes fall through the switch default and are included. So an authority-form/absolute-form target like "http://host:80abc/" parses successfully with m_port==80 (used for the origin connection via port_get() and for the cache key via url_canonicalize_port) while the stored/printed port text is "80abc". The numeric value used for connect and cache-key stays consistent with itself, but the reconstructed/logged URL diverges from the value actually acted upon, and a malformed port is silently accepted rather than rejected.

```
for (auto digit : value) { if (!ParseRules::is_digit(digit)) { break; } unsigned int next = this->m_port * 10 + (digit - '0'); if (next > 65535) { ... return; } this->m_port = static_cast<uint16_t>(next); }  mime_str_u16_set(heap, value, &(this->m_ptr_port), &(this->m_len_port), copy_string);  // stores full 'value' incl. non-digit tail
```

**Fix:** Reject the URL (or at least reject/trim the port) when the port field contains any non-digit character, so the stored port text and m_port cannot disagree and malformed authorities are not silently accepted.

#### [LOW] Response fast path does not require SP after the 3-digit status code
**`src/proxy/hdrs/HTTP.cc:1366`** · _standards-gap_

In http_parser_parse_resp() the fast path validates that cur[8] is a space, that cur[9], cur[10], cur[11] are digits, and that cur[13] is not a space, then computes the status from cur[9..11] and takes the reason phrase starting at cur[13]. It never checks cur[12]. Per RFC 9112 the status-line is HTTP-version SP status-code SP [reason]. A line such as "HTTP/1.1 200Xreason" is accepted with status 200 and the character at cur[12] ('X') silently dropped, rather than the digit-then-SP structure being enforced. This is lenient parsing of an origin/server response line; the slow path is stricter.

```
if ((http_match != 0) || (!(ParseRules::is_digit(cur[5]) && ParseRules::is_digit(cur[7]) && ParseRules::is_digit(cur[9]) && ParseRules::is_digit(cur[10]) && ParseRules::is_digit(cur[11]) && (!ParseRules::is_space(cur[13]))))) { goto slow_case; }  ... HTTPStatus status = static_cast<HTTPStatus>((cur[9]-'0')*100 + (cur[10]-'0')*10 + (cur[11]-'0')); reason_start = &(cur[13]);
```

**Fix:** Add ParseRules::is_space(cur[12]) to the fast-path guard so a malformed status line without the separating SP falls to the slow case (or is rejected) instead of being accepted with a dropped character.

#### [LOW] xpack_decode_string computes Huffman scratch size with a uint32 multiply that can truncate
**`src/proxy/hdrs/XPACK.cc:133`** · _overflow_

encoded_string_len is a uint64_t bounded above by max_string_len and by the remaining input (buf_end - p). For the Huffman branch the scratch buffer size is computed as `uint32_t const str_len = encoded_string_len * 2;` — the multiplication and the assignment both narrow to uint32_t. If a caller ever permits max_string_len (and provides input) at or above 2^31, str_len wraps to a small value while huffman_decode is handed that undersized dst_len; in practice this requires a multi-gigabyte header string so it is not currently exploitable, but the width of the computation is smaller than the uint64_t bound the surrounding checks enforce.

```
uint32_t const str_len = encoded_string_len * 2; *str = arena.str_alloc(str_len); len = huffman_decode(*str, str_len, p, encoded_string_len);
```

**Fix:** Perform the doubling in uint64_t and explicitly reject (or clamp) when the result exceeds what str_alloc/huffman_decode can accept, rather than silently narrowing to uint32_t.


### Plugin API Robustness

_The plugin API's reload-safety net for remap plugins is well designed in outline (thread-local pluginThreadContext refcounts pin the DSO while continuations live) but has concrete holes: the context save/restore uses a shared RemapPluginInfo member that is data-raced by every concurrent doRemap and by config reloads, continuations created from plugin-spawned threads take no DSO reference at all (use-after-dlclose on reload), and the PluginDso zero-refcount deletion decision is not atomic with lookup/acquire during reload. On the API-surface side, sdk_assert validation coverage is uneven (several session/VConn/txn setters dereference unvalidated arguments), TSContCall converts benign lock contention into a whole-server abort while skipping event-count bookkeeping, double-intercept silently leaks PluginVCCores and strands the losing plugin, and TSSslClientContextsNamesGet hands out pointers that dangle across SSL config reloads. No remotely-triggerable critical was found; the worst issues require a plugin plus a reload, which is routine on production fleets._

#### [HIGH ✓verified] Data race on shared RemapPluginInfo::_tempContext corrupts pluginThreadContext save/restore
**`src/proxy/http/remap/RemapPluginInfo.cc:275`** · _race_

setPluginContext()/resetPluginContext() save the previous thread-local pluginThreadContext into a plain instance member `PluginThreadContext *_tempContext` (include/proxy/http/remap/RemapPluginInfo.h:113), not a stack variable or thread-local. RemapPluginInfo::doRemap() (RemapPluginInfo.cc:226/232) runs concurrently on every net thread for every remapped request through the same RemapPluginInfo object, and indicatePreReload()/indicatePostReload() (lines 254, 266) run on the reload (TASK) thread concurrently with in-flight doRemap calls. All of them write and read the single shared _tempContext with no synchronization: this is an unconditional data race (UB) on the production request path. Functionally, when the saved previous context differs between threads (e.g. remap resumed synchronously inside another plugin's continuation callback, where INKContInternal::handle_event has set pluginThreadContext), one thread can restore another thread's saved value: a thread can end up with a wrong or null pluginThreadContext, so a subsequent TSContCreate (InkAPI.cc:3407-3413) either fails to take a DSO refcount (continuation outlives the plugin -> call into a dlclose'd DSO after remap reload) or pins/attributes the wrong plugin.

```
RemapPluginInfo.cc:275-288:
inline void
RemapPluginInfo::setPluginContext()
{
  _tempContext        = pluginThreadContext;
  pluginThreadContext = this;
  ...
}
inline void
RemapPluginInfo::resetPluginContext()
{
  ...
  pluginThreadContext = _tempContext;
}
RemapPluginInfo.h:113:  PluginThreadContext *_tempContext = nullptr;
```

**Fix:** Save the previous context in a stack local inside each entry point (doRemap, osResponse, initInstance, doneInstance, indicatePre/PostReload) instead of a member, e.g. `auto *prev = pluginThreadContext; pluginThreadContext = this; ...; pluginThreadContext = prev;` mirroring what INKContInternal::handle_event already does. Delete _tempContext.

**Verification:** The race is real and unguarded. (1) Shared object: RemapPluginInst::doRemap (src/proxy/http/remap/PluginFactory.cc:76-78) calls _plugin.doRemap on the single per-DSO RemapPluginInfo shared by all remap rules and all net threads; setPluginContext/resetPluginContext (RemapPluginInfo.cc:275-288) do plain unsynchronized read/write of the shared member _tempContext (RemapPluginInfo.h:113). No mutex exists in RemapPluginInfo/PluginDso for these paths; the EThread/continuation-mutex defense does not apply because concurrent HttpSMs hold distinct mutexes, and indicatePreReload/indicatePostReload run on the config-reload path (RemapConfig.cc:1566,1573 -> PluginDso.cc:385,404) over the same objects concurrently with in-flight doRemap. That makes it an unconditional C++ data race (UB) on the request path. (2) The functional corruption scenario traced end-to-end: INKContInternal::handle_event sets thread-local pluginThreadContext around every plugin callback (src/api/InkContInternal.cc:158-166); a plugin at READ_REQUEST_HDR/PRE_REMAP calling TSHttpTxnReenable synchronously inside its handler takes the direct path (same thread, recursive SM-mutex trylock succeeds) into sm->state_api_callback (src/api/InkAPI.cc:5230-5235), which runs state_api_callout -> handle_api_return -> set_next_state -> REMAP_REQUEST -> do_remap_request(true) inline (src/proxy/http/HttpSM.cc:1412-1442, 8308) on the plugin callback's stack with pluginThreadContext non-null. A concurrent doRemap on another thread then clobbers _tempContext, so one thread restores null (losing the hook plugin's context) or the other thread restores a foreign non-null context into its thread-local; a subsequent TSContCreate (InkAPI.cc:3407-3413) then skips or misattributes the DSO acquire(), matching the claimed refcount/lifetime consequence.

**Verifier correction:** Severity nuance only: in the common interleaving both threads save/restore nullptr, so the race, while formally UB, is value-invisible; the harmful outcome additionally requires a hook plugin that calls plugin APIs after a synchronous TSHttpTxnReenable (the corruption window closes when INKContInternal::handle_event's stack-saved restore at InkContInternal.cc:166 unwinds) and dynamic plugin reload/unload for the dangling-DSO endgame. Real bug, narrow practical window.

#### [HIGH ✓verified] Continuations created off plugin context (e.g. TSThreadCreate threads) escape the remap-reload DSO refcount, allowing use-after-dlclose
**`src/api/InkAPI.cc:3407`** · _use-after-free_

The only thing that keeps a dynamically-reloadable remap plugin's DSO mapped while its continuations are live is the thread-local pluginThreadContext refcount taken in TSContCreate. That thread-local is set only when the core dispatches into the plugin (INKContInternal::handle_event, RemapPluginInfo::setPluginContext). It is never propagated to threads the plugin spawns with TSThreadCreate (src/api/InkIOCoreAPI.cc:135-154 copies only func/data into INKThreadInternal), nor to any other non-dispatch context (e.g. an OpenSSL/library callback thread). A TSCont created there gets m_context == nullptr, holds no reference on the RemapPluginInfo, and once the old config's instances are released after a remap.config reload (dynamic reload is on by default: proxy.config.plugin.dynamic_reload_mode = 1, src/records/RecordsConfig.cc:1142), PluginDso::release() drops the refcount to 0 and the DSO is dlclose'd (PluginDso.cc:296-299, 70-75). The still-scheduled continuation then fires and INKContInternal::handle_event calls m_event_func into unmapped memory (InkContInternal.cc:165) — a crash on a production box that merely reloaded remap.config. Nothing enforces or documents that TSContCreate from plugin-owned threads is unsafe for reloadable remap plugins.

```
InkAPI.cc:3407-3413:
  if (pluginThreadContext) {
    pluginThreadContext->acquire();
  }
  INKContInternal *i = THREAD_ALLOC(INKContAllocator, this_thread());
  i->init(funcp, mutexp, pluginThreadContext);
InkIOCoreAPI.cc:145-146:
  thread->func = func;
  thread->data = data;  // no pluginThreadContext capture
```

**Fix:** Capture the creating plugin's context in TSThreadCreate and install it as the spawned thread's pluginThreadContext for the thread's lifetime (acquire/release around the trampoline), or at minimum document loudly that continuations created outside core-dispatched callbacks do not pin the DSO and force such plugins to opt out via TSPluginDSOReloadEnable(0).

**Verification:** Traced end-to-end; every link in the claimed chain checks out and no guard exists. (1) TSContCreate (src/api/InkAPI.cc:3407-3413) takes the DSO reference solely from the thread-local pluginThreadContext; a null context means the continuation holds no reference (TSContDestroy releases only if m_context is set, InkAPI.cc:3424-3426). (2) That thread-local (declared `thread_local PluginThreadContext *pluginThreadContext = nullptr` at src/proxy/ReverseProxy.cc:82, so it zero-initializes on every new thread) is set only around core->plugin dispatch: INKContInternal::handle_event (src/api/InkContInternal.cc:158-166), RemapPluginInfo::setPluginContext (src/proxy/http/remap/RemapPluginInfo.cc:278-287), and global-plugin init (src/proxy/Plugin.cc:252-257). (3) TSThreadCreate (src/api/InkIOCoreAPI.cc:135-154) and its trampoline (lines 113-129) copy only func/data and call ithread->set_specific(); pluginThreadContext is never propagated, so TSContCreate on such a thread produces m_context == nullptr — exactly as claimed. (4) The DSO refcount is held only by RemapPluginInst (acquire/release in src/proxy/http/remap/PluginFactory.cc:44,49) and context-carrying continuations; RemapPluginInfo : PluginDso : PluginThreadContext (include/proxy/http/remap/PluginDso.h:58, RemapPluginInfo.h:52), so those are the same counter. (5) On reload with dynamic reload enabled (default "1", src/records/RecordsConfig.cc:1142), an updated .so (mtime differs, findByEffectivePath check at PluginDso.cc:358-375) or a removed plugin means the old PluginDso is not reused; when the old UrlRewrite drains, ~UrlRewrite calls pluginFactory.deactivate() (src/proxy/http/remap/UrlRewrite.cc:185) and ~PluginFactory deletes all RemapPluginInsts (PluginFactory.cc:102-105) -> PluginDso::release() hits 0 (PluginDso.cc:292-300) -> LoadedPlugins::remove schedules DeleterContinuation -> ~PluginDso -> unload() -> dlclose (PluginDso.cc:70-75, 158-179; dlopen used RTLD_NOW|RTLD_LOCAL with no RTLD_NODELETE, so the text segment is unmapped). (6) The orphaned continuation then fires: EThread::process_event's mutex acquisition protects only the ProxyMutex (core-allocated memory, still valid) — it is not a guard here — and INKContInternal::handle_event calls m_event_func into unmapped memory (InkContInternal.cc:165). I looked for refuting guards and found none: the opt-out table (PluginDso.cc:409-425, TSPluginDSOReloadEnable) is plugin-opt-in, not automatic; the design doc (doc/developer-guide/design-documents/reloading-plugins.en.rst:117-128) confirms the thread-local context is the *only* mechanism ("keep things hidden from the plugin developer by using thread local plugin context") and neither it nor doc/developer-guide/api/functions/TSThreadCreate.en.rst mentions the plugin-spawned-thread gap, supporting the "nothing documents this" assertion. The one scenario constraint (not a refutation): if the .so file is unchanged AND still referenced by the new config, findByEffectivePath reuses the same PluginDso and the refcount never reaches 0 — the crash requires the plugin to be removed from remap.config or its .so updated before the reload, which is precisely the upgrade workflow dynamic reload exists to serve.

#### [MEDIUM] TOCTOU between PluginDso::release() zero-refcount deletion and findByEffectivePath()+acquire() can resurrect a dying DSO
**`src/proxy/http/remap/PluginDso.cc:296`** · _race_

PluginDso::release() decides to delete on `0 == this->refcount_dec()` without holding LoadedPlugins::_mutex; only afterwards does remove() take the mutex, erase the plugin, and schedule a DeleterContinuation (PluginDso.cc:337-351). Meanwhile PluginFactory::getRemapPlugin() on the reload thread does findByEffectivePath() under the mutex (PluginDso.cc:358-375) and then calls acquire() outside it, in the RemapPluginInst constructor (PluginFactory.cc:42-45). Interleaving: net thread T1 (tearing down an old UrlRewrite config whose last transaction just finished) drops the refcount to 0; before T1 enters remove(), reload thread T2 finds the same PluginDso in the list and returns it; T1 erases it and schedules deletion; T2 then acquire()s the doomed object (0 -> 1) and hands out a RemapPluginInst referring to a PluginDso that is deleted (and dlclose'd) one event-loop later — use-after-free on every subsequent doRemap through that instance. Reachable when back-to-back remap reloads overlap with old-config teardown on net threads (config teardown is refcount-driven and runs on whatever thread releases the last transaction).

```
PluginDso.cc:293-300:
void
PluginDso::release()
{
  ...
  if (0 == this->refcount_dec()) {
    ...
    _plugins->remove(this);
  }
}
PluginFactory.cc:42-45:
RemapPluginInst::RemapPluginInst(RemapPluginInfo &plugin) : _plugin(plugin)
{
  _plugin.acquire();
}
```

**Fix:** Make find-and-acquire atomic: have LoadedPlugins::findByEffectivePath() call acquire() while still holding _mutex and skip entries whose refcount is already 0 (or perform the refcount_dec-to-zero check and list erase under the same _mutex so a concurrent finder either sees the entry gone or safely bumps it from a nonzero count).

#### [MEDIUM] TSContCall aborts the whole server on benign lock contention and skips m_event_count bookkeeping
**`src/api/InkAPI.cc:3755`** · _logic-bug_

TSContCall is the only continuation API with no sdk_assert on contp, and on a failed try-lock of the target continuation's mutex it executes ink_release_assert(0), turning ordinary cross-thread lock contention (e.g. a lua/fetch plugin calling another continuation whose mutex is momentarily held elsewhere) into a full traffic_server crash instead of an error return the plugin could handle. Additionally it invokes handleEvent() directly without the m_event_count increment that APIHook::invoke() (src/api/APIHook.cc:50-53) and TSContSchedule* perform, while INKContInternal::handle_event_count() (InkContInternal.cc:133-141) unconditionally decrements for EVENT_IMMEDIATE/EVENT_INTERVAL/TS_EVENT_HTTP_TXN_CLOSE; a plugin passing TS_EVENT_IMMEDIATE to TSContCall on a TSCont drives m_event_count negative, skewing the m_deletable computation so a later TSContDestroy can free the continuation while an event is still outstanding (use-after-free / 'continuation which is deleted' release assert) or never free it (leak).

```
InkAPI.cc:3755-3763:
TSContCall(TSCont contp, TSEvent event, void *edata)
{
  Continuation *c = reinterpret_cast<Continuation *>(contp);
  WEAK_MUTEX_TRY_LOCK(lock, c->mutex, this_ethread());
  if (!lock.is_locked()) {
    // If we cannot get the lock, the caller needs to restructure to handle rescheduling
    ink_release_assert(0);
  }
  return c->handleEvent(static_cast<int>(event), edata);
}
```

**Fix:** Add sdk_assert(sdk_sanity_check_iocore_structure(contp)); return an error (or blocking-lock like APIHook::blocking_invoke) instead of ink_release_assert on contention; and when the target is an INKContInternal, pre-increment m_event_count for the events handle_event_count() will decrement.

#### [MEDIUM] Second TSHttpTxnIntercept/TSHttpTxnServerIntercept on a transaction leaks the prior PluginVCCore and strands the first interceptor
**`src/api/InkAPI.cc:6115`** · _memory-bug_

Both intercept APIs unconditionally overwrite http_sm->plugin_tunnel with a freshly allocated PluginVCCore. If two plugins (or one buggy plugin) intercept the same transaction — e.g. two READ_REQUEST_HDR hook plugins each calling TSHttpTxnIntercept — the previously stored PluginVCCore is orphaned: HttpSM only ever frees the current pointer (HttpSM.cc:7898-7900 and 7981-7983 call kill_no_connect() on plugin_tunnel; HttpSM.cc:5714-5717 consumes it at connect time), so the first core (with its ProxyMutex and buffer settings, PluginVC.cc:1011-1022) leaks on every such request, and the first plugin's accept continuation never receives TS_EVENT_NET_ACCEPT, so any per-transaction state it parked for that intercept leaks or waits forever. There is no error return or diagnostic for this misuse.

```
InkAPI.cc:6114-6115 (and identically 6129-6130):
  http_sm->plugin_tunnel_type = HttpPluginTunnel_t::AS_SERVER;
  http_sm->plugin_tunnel      = PluginVCCore::alloc(reinterpret_cast<INKContInternal *>(contp), buffer_index, buffer_water_mark);
```

**Fix:** In both APIs, if http_sm->plugin_tunnel is already set, either kill_no_connect() the old core before overwriting or (better) log an error and ignore the second intercept; consider changing the API to return TSReturnCode so plugins can detect the conflict.

#### [MEDIUM] TSSslClientContextsNamesGet returns pointers into config-owned strings that dangle after SSL config reload
**`src/api/InkAPI.cc:8159`** · _use-after-free_

The function fills the caller's result array with string_view::data() pointers taken from the keys of params->top_level_ctx_map, then immediately calls SSLConfig::release(params) and returns. The function keeps no reference on behalf of the caller: as soon as an ssl_multicert/records reload retires that SSLConfigParams generation and the last other reference drops, the std::string keys backing every returned const char* are destroyed, and the plugin holds dangling pointers. The API's documented usage pattern ('call TSSslClientContextsNamesGet first to determine which lookup keys are present before querying') encourages holding these pointers across calls, exactly the window in which a reload frees them. Nothing in ts.h or the function copies the names or warns about the lifetime.

```
InkAPI.cc:8146-8166:
    auto  mem = static_cast<std::string_view *>(alloca(sizeof(std::string_view) * n));
    ...
    for (int i = 0; i < idx; i++) {
      result[i] = mem[i].data();
    }
  }
  ...
  SSLConfig::release(params);
  return TS_SUCCESS;
```

**Fix:** Copy the names into TSmalloc'd storage the caller frees (matching TSSslSecretGet's contract), or document that the pointers are only valid until the next SSL configuration reload and provide a lifetime-safe variant.

#### [LOW] Inconsistent sdk_assert coverage: several session/VConn/txn APIs dereference unvalidated plugin arguments
**`src/api/InkAPI.cc:3825`** · _quality_

A cluster of TS APIs skip the sdk_assert argument validation that every sibling API performs, so plugin misuse produces a raw segfault (or worse, silent UB) instead of the diagnostic release-assert the SDK convention promises. Confirmed cases: TSHttpSsnClientVConnGet/TSHttpSsnServerVConnGet (InkAPI.cc:3824-3832) call cs->get_netvc() with no sdk_sanity_check_http_ssn, unlike TSHttpSsnHookAdd at 3805; TSVConnSslConnectionGet (7936-7945) and TSVConnSslVerifyCTXGet (8008-8017) dereference the vconn with no null/sanity check while the adjacent TSVConnSslSniGet (7955) and TSVConnFdGet (7950) do check; TSHttpTxnResponseActionSet (8842-8849) dereferences both txnp and *action with no checks even though its own comment says 'The passed *action must not be null'; TSSslSecretGet (8104-8110) dereferences params->secrets without a null check when both SSLConfig::load_acquire() and SSLConfig::acquire() return nullptr (early startup). Each is a crash-on-misuse without the standard diagnostic, and the inconsistency itself misleads plugin authors about which APIs validate.

```
InkAPI.cc:3824-3828:
TSVConn
TSHttpSsnClientVConnGet(TSHttpSsn ssnp)
{
  ProxySession *cs = reinterpret_cast<ProxySession *>(ssnp);
  return reinterpret_cast<TSVConn>(cs->get_netvc());
InkAPI.cc:8845-8848:
  HttpSM              *sm    = reinterpret_cast<HttpSM *>(txnp);
  HttpTransact::State *s     = &(sm->t_state);
  s->response_action.handled = true;
  s->response_action.action  = *action;
```

**Fix:** Add the standard sdk_assert(sdk_sanity_check_*) calls (ssn, null_ptr) to these entry points, and a null guard in TSSslSecretGet returning nullptr with *secret_data_length = 0 when no SSLConfigParams is available.


### HTTP Standards Conformance & Missing Features

_ATS's HTTP conformance is strong on the classics but trails the 2021-2024 RFC wave. Confirmed supported: 103 Early Hints forwarding (HttpTransact.cc:4320-4322 routes EARLY_HINTS through the 1xx forwarding path), RFC 9213 targeted cache control with CDN-Cache-Control default (RecordsConfig.cc:667), zstd content-encoding in the compress plugin (plugins/compress/zstd_compress.cc), TLS 1.3 0-RTT with RFC 8470 Early-Data/425 handling, and an RFC 9111-correct Age calculation (HttpTransactCache.cc:614-669). Confirmed absent: QUERY method, RFC 8441/9220 Extended CONNECT (h2/h3 WebSockets), RFC 9218 priorities (only the deprecated 7540 tree), RFC 9211 Cache-Status, core RFC 5861 stale-while-revalidate/stale-if-error (experimental plugin only), RFC 8941 structured fields, RFC 8336 ORIGIN frame, must-understand (safe-by-default omission), and ECH. The most serious issue found is a genuine RFC 9111 violation: the qualified directives private="field"/no-cache="field" are discarded wholesale by the Cache-Control cooking logic in MIME.cc, so a shared ATS cache can store and serve responses the origin marked private — the RFC mandates falling back to the unqualified form._

#### [HIGH] Qualified private="field"/no-cache="field" directives are discarded entirely, allowing shared-cache storage of private responses
**`src/proxy/hdrs/MIME.cc:3833`** · _standards-gap_

In MIMEHdrImpl::recompute_cooked_stuff, after a well-known Cache-Control token is recognized and its mask bit set (line 3765), any trailing non-whitespace content causes the just-set mask bits to be cleared (lines 3833-3841). This 'ignore unrecognized directive' logic (added for issue #12029, semicolon separators) also fires for the RFC-valid qualified forms 'private="Set-Cookie"' and 'no-cache="Set-Cookie"': the token parses as private/no-cache, then c points at '=', which is non-whitespace, so csv_value_mask is reverted. RFC 9111 Section 5.2.2.7 says a shared cache that does not implement the field-name form of private MUST NOT store the response, and Section 5.2.2.4 says the same for no-cache (must not be used without revalidation). ATS instead drops the directive completely: response_cacheable_indicated_by_cc (src/proxy/http/HttpTransact.cc:6561-6563) then sees no CC_PRIVATE bit, so 'Cache-Control: private="Set-Cookie", max-age=600' is judged cacheable (+1 via max-age) and a per-user response can be cached and served to other users. Only the exact string 'private,no-cache' is special-cased on the fastpath (line 3738). There is no unit-test coverage for the qualified forms in src/proxy/hdrs/unit_tests/test_HdrUtils.cc (tests only cover malformed max-age variants).

```
src/proxy/hdrs/MIME.cc:3830-3841:
            while (c < e && ParseRules::is_ws(*c)) {
              ++c;
            }
            if (c < e) {
              // There's non-whitespace content that wasn't parsed. ...
              // Per RFC 7234 Section 5.2: "A cache MUST ignore unrecognized cache
              // directives."
              if (csv_value_mask != 0) {
                // Reverse the mask that we set above.
                m_cooked_stuff.m_cache_control.m_mask &= ~csv_value_mask;
              }
            }
and src/proxy/http/HttpTransact.cc:6561-6563:
  cc_mask = MIME_COOKED_MASK_CC_PRIVATE | (ignore_no_store_and_no_cache_directives ? 0 : MIME_COOKED_MASK_CC_NO_STORE);
  if (response->get_cooked_cc_mask() & cc_mask) {
    return -1;
```

**Fix:** In the trailing-content check, special-case directives whose qualified (field-name argument) form is defined by RFC 9111 — private and no-cache — and fall back to treating them as unqualified (keep the mask bit set) instead of clearing it. Add unit tests for 'Cache-Control: private="Set-Cookie"' and 'no-cache="Set-Cookie"' asserting CC_PRIVATE/CC_NO_CACHE remain set.

#### [MEDIUM] HTTP QUERY method (draft-ietf-httpbis-safe-method-w-body) absent from well-known method table
**`src/proxy/hdrs/HdrToken.cc:113`** · _missing-feature_

The static well-known method list contains only CONNECT, DELETE, GET, POST, HEAD, OPTIONS, PURGE, PUT, TRACE and the ATS-proprietary PUSH; QUERY is absent both here and in the HTTP_METHOD_*/HTTP_WKSIDX_* initialization in src/proxy/hdrs/HTTP.cc:147-178. A QUERY request is therefore treated as an unknown method: it is proxied, but HttpTransactHeaders::is_method_cacheable and the GET-centric checks (e.g. src/proxy/http/HttpTransact.cc:3183, 6327) mean QUERY responses are never cached, defeating the primary purpose of the method (a safe, cacheable GET-with-body), and per-method stats/ACL matching cannot reference it. As QUERY approaches RFC status and origins/CDNs adopt it, ATS as a caching proxy will silently degrade to pass-through for that traffic.

```
src/proxy/hdrs/HdrToken.cc:113:
  "CONNECT", "DELETE", "GET", "POST", "HEAD", "OPTIONS", "PURGE", "PUT", "TRACE", "PUSH",
src/proxy/hdrs/HTTP.cc:147-156 initializes only these ten methods (no QUERY).
```

**Fix:** Add QUERY to the hdrtoken static method tables and HTTP_WKSIDX_* set, and design cache-key semantics (key must incorporate a digest of the request content per the draft) before enabling caching for it; at minimum register the token so stats, ACLs, and plugins can match it.

#### [MEDIUM] RFC 8441 Extended CONNECT not implemented: no WebSockets over HTTP/2 or HTTP/3
**`include/proxy/http2/HTTP2.h:253`** · _missing-feature_

The Http2SettingsIdentifier enum ends at HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE = 6; SETTINGS_ENABLE_CONNECT_PROTOCOL (0x8) is not defined, and a repo-wide search for ':protocol', 'ENABLE_CONNECT_PROTOCOL', or RFC 8441 in src/proxy/http2 finds nothing. The HTTP/3 side likewise has no SETTINGS_ENABLE_CONNECT_PROTOCOL (include/proxy/http3/Http3Frame.h:144-148 lists only HEADER_TABLE_SIZE, MAX_FIELD_SECTION_SIZE, QPACK_BLOCKED_STREAMS, NUM_PLACEHOLDERS), so RFC 9220 is also unsupported. WebSocket upgrade is only handled on HTTP/1.1 via the Upgrade header path (src/proxy/http/HttpTransact.cc:1421-1429). Browsers negotiate WebSockets over h2/h3 when the server advertises the setting; clients connecting to ATS over HTTP/2 must fall back to a separate HTTP/1.1 connection for WebSockets, and cannot do so at all if the deployment forces h2.

```
include/proxy/http2/HTTP2.h:253-260:
enum Http2SettingsIdentifier {
  HTTP2_SETTINGS_HEADER_TABLE_SIZE      = 1,
  HTTP2_SETTINGS_ENABLE_PUSH            = 2,
  HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS = 3,
  HTTP2_SETTINGS_INITIAL_WINDOW_SIZE    = 4,
  HTTP2_SETTINGS_MAX_FRAME_SIZE         = 5,
  HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE   = 6,
  HTTP2_SETTINGS_MAX, ...
```

**Fix:** Implement SETTINGS_ENABLE_CONNECT_PROTOCOL and the :protocol pseudo-header in the h2 request translation (http2_convert_header_from_2_to_1_1), mapping extended CONNECT to the existing HTTP/1.1 websocket upgrade/tunnel machinery, gated by a records.yaml toggle.

#### [MEDIUM] RFC 9218 Extensible Priorities not implemented (no PRIORITY_UPDATE frame, no Priority header); only deprecated RFC 7540 priority tree
**`include/proxy/http2/HTTP2.h:176`** · _missing-feature_

The HTTP/2 frame-type constants stop at HTTP2_FRAME_TYPE_CONTINUATION = 9; PRIORITY_UPDATE (0x10) is not defined, SETTINGS_NO_RFC7540_PRIORITIES (0x9) is absent from the settings enum, and there is no parsing of the 'Priority' request header (urgency/incremental) anywhere in src (grep for PRIORITY_UPDATE/urgency/incremental returns only a TODO). ATS instead retains the RFC 7540 stream-dependency tree, which RFC 9113 deprecated and major browsers (Chrome, Firefox, Safari) have abandoned in favor of RFC 9218 for both h2 and h3. For HTTP/3, src/proxy/http3/Http3SettingsHandler.cc:81 carries only '// TODO: update settings for priority tree'. Result: client-signaled prioritization is ignored for modern clients, degrading page-load performance characteristics through the proxy.

```
include/proxy/http2/HTTP2.h:176-178:
  HTTP2_FRAME_TYPE_GOAWAY        = 7,
  ...
  HTTP2_FRAME_TYPE_CONTINUATION  = 9,
src/proxy/http3/Http3SettingsHandler.cc:81:
    // TODO: update settings for priority tree
```

**Fix:** Add PRIORITY_UPDATE frame handling and Priority header parsing (urgency 0-7, incremental flag), advertise SETTINGS_NO_RFC7540_PRIORITIES, and feed the values into the existing write-scheduling logic; this also requires an RFC 8941 structured-field item parser (see separate finding).

#### [MEDIUM] RFC 5861 stale-while-revalidate / stale-if-error not supported in core cache logic, only via experimental plugin
**`include/proxy/hdrs/MIME.h:214`** · _missing-feature_

The cooked Cache-Control mask enum has no bits for stale-while-revalidate or stale-if-error, and recompute_cooked_stuff (src/proxy/hdrs/MIME.cc:3744-3845) only extracts max-age, min-fresh, max-stale, and s-maxage numeric values, so the core freshness logic in HttpTransact (what_is_document_freshness, can-serve-stale via proxy.config.http.cache.max_stale_age) never sees these origin directives. Support exists only in plugins/experimental/stale_response/ (DirectiveParser.cc re-parses Cache-Control itself), which is experimental, must be explicitly loaded, and duplicates header parsing. Origins that rely on RFC 5861 semantics (standard on other CDNs: Fastly, Cloudflare, Varnish) get no async-revalidation or stale-on-5xx behavior from a stock ATS install, and the global max_stale_age knob is not per-object as the RFC requires.

```
include/proxy/hdrs/MIME.h:214-227 enum ends at:
  MIME_COOKED_MASK_CC_S_MAXAGE             = (1 << 11),
  MIME_COOKED_MASK_CC_NEED_REVALIDATE_ONCE = (1 << 12),
  MIME_COOKED_MASK_CC_EXTENSION            = (1 << 13)
(no SWR/SIE bits); plugins/experimental/stale_response/DirectiveParser.cc implements its own stale-while-revalidate/stale-if-error parsing.
```

**Fix:** Cook stale-while-revalidate and stale-if-error values in MIMEHdrImpl::recompute_cooked_stuff alongside max-age/s-maxage, and honor them in HttpTransact freshness/serve-stale decisions (per-object override of cache_max_stale_age), promoting the stale_response behavior into core.

#### [LOW] RFC 9211 Cache-Status response header not implemented; only proprietary Via encoding exposes cache results
**`src/proxy/http/HttpTransactHeaders.cc:454`** · _missing-feature_

ATS reports cache disposition exclusively through its proprietary compact Via-tag encoding (generate_and_set_squid_codes / insert_via_header_in_response decoding VIA_CACHE_RESULT chars) and squid log codes; a repo-wide search for 'Cache-Status' in src/ finds no producer of the RFC 9211 standard header (only example cripts scripts set one manually). By contrast, targeted cache control RFC 9213 IS implemented (src/records/RecordsConfig.cc:667 'proxy.config.http.cache.targeted_cache_control_headers' defaulting to CDN-Cache-Control). Operators debugging multi-layer CDN chains increasingly rely on the standardized Cache-Status hit/fwd/ttl/collapsed parameters, which interoperate across vendors; ATS's cryptic Via string requires the traffic_via decoder tool and is often stripped for privacy.

```
src/proxy/http/HttpTransactHeaders.cc:454:
HttpTransactHeaders::generate_and_set_squid_codes(HTTPHdr *header, char *via_string, HttpTransact::SquidLogInfo *squid_codes)
(no Cache-Status emission anywhere in src/proxy).
```

**Fix:** Add an opt-in records.yaml setting to append an RFC 9211 'Cache-Status: <name>; hit|fwd=<reason>; ttl=<n>' entry derived from the same state that feeds the Via cache-result character and squid codes.

#### [LOW] TLS Encrypted Client Hello (ECH) entirely absent from the TLS stack
**`src/iocore/net/P_SSLConfig.h:109`** · _missing-feature_

There is no ECH support anywhere in src/iocore/net: no SSL_ech_*/SSL_set1_ech_config_list calls, no ECH key/config file handling in SSLUtils.cc or SSLConfig.cc, and no ECH action in sni.yaml processing (YamlSNIConfig.cc), even though the SNI-based routing layer is exactly where ECH termination (decrypting the inner ClientHello) would need to hook in. By contrast, TLS 1.3 0-RTT early data is fully supported: server_max_early_data config, TLSEarlyDataSupport.cc, per-SNI overrides (SNIActionPerformer.cc:477-480), and RFC 8470 conformance in the HTTP layer (early-data requests restricted to safe methods with 425 Too Early responses, src/proxy/http/HttpSM.cc:766-780, HttpTransact.cc:1052). As browsers ship ECH and BoringSSL/OpenSSL 3.5+ expose APIs, ATS deployments doing SNI-based routing/blocking will be blind to ECH inner names.

```
src/iocore/net/P_SSLConfig.h:109-111 shows the early-data feature surface with no ECH counterpart:
  static uint32_t server_max_early_data;
  ...
  static bool     server_allow_early_data_params;
(grep for 'ECH'/'ech_' across src/iocore/net matches only 'ECHO' terminal-flag code in SSLUtils.cc:655).
```

**Fix:** Track OpenSSL 3.5/BoringSSL ECH APIs: add ECHConfig key management to ssl_multicert/sni.yaml, decrypt inner ClientHello before SNI actions run, and expose retry-config serving; document non-support until then.

#### [LOW] No RFC 8941 Structured Fields parser; targeted cache-control headers parsed with legacy comma-splitting parser
**`src/proxy/hdrs/MIME.cc:3718`** · _standards-gap_

The codebase has no RFC 8941 structured-field parser (no sf-item/sf-list/sf-dictionary handling in src/proxy/hdrs; grep for 8941/StructuredField finds only unrelated test data). This is both a missing building block for other standards ATS lacks (RFC 9218 Priority, RFC 9211 Cache-Status, RFC 8942 Client Hints negotiation are all Structured Fields) and a latent conformance gap in what IS implemented: RFC 9213 defines CDN-Cache-Control as a Structured Field Dictionary, but the targeted-header lookup feeds the value into the same legacy HdrCsvIter cooked Cache-Control parser used since RFC 2616, so SF constructs that are valid per RFC 9213 (e.g. parameters on a dictionary member, or sf-token values) are treated as malformed and, per the trailing-content logic at lines 3833-3841, the directive is dropped instead of being interpreted per SF parsing rules.

```
src/proxy/hdrs/MIME.cc:3717-3727:
    // Check for targeted cache control headers first (in priority order).
    for (size_t i = 0; i < targeted_headers_count; ++i) {
      field = mime_hdr_field_find(this, targeted_headers[i]);
      ...
    // If no targeted header was found, fall back to standard Cache-Control.
    if (!field) {
      field = mime_hdr_field_find(this, static_cast<std::string_view>(MIME_FIELD_CACHE_CONTROL));
    }
```

**Fix:** Add a small RFC 8941 parser to tsutil (items, lists, dictionaries with parameters) and use it for targeted cache-control headers per RFC 9213 Section 2.1; reuse it when implementing Priority and Cache-Status.


### Performance (per-request hot paths)

_The per-request hot paths are mostly well engineered (freelist allocators, incremental header parsing, WKS presence-bit/slot-accelerator field lookup, CAS-based log buffers), but several concrete per-request costs remain. The most serious is an attacker-amplifiable O(n^2) duplicate-check during MIME header parsing for non-well-known field names, bounded only by header byte size, not field count. Cross-thread synchronization per transaction also shows up in the libstdc++ mutex-pool-backed atomic shared_ptr load of the remap table in HttpSM::init and in globally shared atomic stat counters updated on every read/write syscall. Additional avoidable work per request includes a discarded-result SNI policy scan with wildcard PCRE matches on every HTTPS request, a heap-allocating std::string temporary in the remap host-table lookup, a cache-hostile 2KB-node trie walked per path character, per-acquire MD5 hashing of hostnames for the session pool, and double evaluation of every log field per entry._

#### [HIGH] O(n^2) duplicate-check walk while parsing headers with many non-well-known field names
**`src/proxy/hdrs/MIME.cc:1396`** · _performance_

Every field parsed by mime_parser_parse is attached with check_for_dups=1 (MIME.cc:2573 'mime_hdr_field_attach(mh, field, 1, nullptr)'), and mime_hdr_field_attach then calls mime_hdr_field_find for the new field's name. For names that are not well-known tokens (no presence bits, no slot accelerator), mime_hdr_field_find falls through to _mime_hdr_field_list_search_by_string (MIME.cc:1156-1177), which walks every field slot in every block doing ts::iequals. With k distinct custom header names in one message this makes header parsing O(k^2). There is no header field-count limit (only proxy.config.http.request_header_max_size, default 32768 per src/records/RecordsConfig.cc:585), so a 32KB request of ~3500 short distinct custom headers forces ~6M slot visits with case-insensitive compares — attacker-controlled milliseconds of CPU per request on every net thread, on both the request parse and the origin response parse. WKS fields whose slot id exceeds the accelerator range hit the same full walk via _mime_hdr_field_list_search_by_wks (MIME.cc:1133-1153).

```
MIME.cc:1394-1396: if (check_for_dups || ...) { std::string_view name{field->name_get()}; prev_dup = mime_hdr_field_find(mh, name); ... MIME.cc:1269: MIMEField *f = _mime_hdr_field_list_search_by_string(mh, field_name); ... MIME.cc:1162-1173: for (fblock = &(mh->m_first_fblock); fblock != nullptr; fblock = fblock->m_next) { ... while (field < too_far_field) { if (field->is_live() && ts::iequals(...)) ...
```

**Fix:** Bound the quadratic behavior: keep a small per-parse hash of seen non-WKS names (or a per-header bloom/presence filter for non-WKS names) so the dup check is O(1) amortized; alternatively add a configurable max field count and skip the dup search entirely during initial parse by attaching with check_for_dups=0 and linking dups in a single post-pass.

#### [MEDIUM] Per-transaction atomic shared_ptr load of the global remap table serializes all net threads on one lock
**`src/proxy/http/HttpSM.cc:331`** · _performance_

HttpSM::init runs once per transaction and does 'm_remap = rewrite_table.load(std::memory_order_acquire)'. AtomicSharedPtr::load (include/tsutil/AtomicSharedPtr.h:63) is implemented with std::atomic_load_explicit on a std::shared_ptr, which libstdc++ implements with a small hashed pool of global mutexes (_Sp_locker); every load of the same object address maps to the same mutex, so all ET_NET threads serialize on one process-global mutex at the start of every transaction. In addition, the shared_ptr copy increments and (at SM teardown) decrements the same control-block refcount cache line from all threads. This is a per-request global synchronization point that only needs to change on 'traffic_ctl config reload' of remap.config.

```
HttpSM.cc:331: m_remap = rewrite_table.load(std::memory_order_acquire); include/tsutil/AtomicSharedPtr.h:61-64: load(...) { return std::atomic_load_explicit(&_p, order); }
```

**Fix:** Cache the shared_ptr per EThread and refresh it via a cheap generation counter (or hazard-pointer/RCU-style epoch) so the mutex-pool path and shared refcount are touched once per reload per thread, not once per transaction; alternatively use a thread-local lease renewed from the event loop.

#### [MEDIUM] check_sni_host re-evaluates the sni.yaml action lookup on every HTTPS request, even when the policy result is discarded
**`src/proxy/http/HttpSM.cc:4649`** · _performance_

check_sni_host runs before remap for every HTTPS request (called from do_remap_request, HttpSM.cc:4691). The condition is written as 'would_have_actions_for(...) && host_sni_policy > 0', so the expensive lookup executes first and its result is thrown away when the admin has disabled the feature (host_sni_policy == 0). The lookup itself is costly per request: 'std::string{host_name}.c_str()' heap-allocates for any Host longer than the SSO limit just to get a null terminator; SNIConfigParams::get then lowercases the name, builds another temporary std::string for unordered_multimap<std::string,...>::equal_range (src/iocore/net/SSLSNIConfig.cc:214), and linearly runs a PCRE full-match against every wildcard entry in sni_action_list (SSLSNIConfig.cc:233-255). This repeats per request the same policy evaluation already done once at TLS handshake, scaling with the number of wildcard sni.yaml entries.

```
HttpSM.cc:4649-4650: if (snis->would_have_actions_for(std::string{host_name}.c_str(), netvc->get_remote_endpoint(), host_sni_policy) && host_sni_policy > 0) { ... SSLSNIConfig.cc:233-240: for (auto const &retval : sni_action_list) { ... } else if (retval.match.exec(servername, matches, RE_FULL_MATCH) >= 0) {
```

**Fix:** Swap the operands so the policy flag short-circuits the lookup; change would_have_actions_for to take std::string_view (SNIConfigParams::get already copies into a stack buffer); give sni_action_map a transparent hasher; consider caching the handshake-time SNI action match on the TLSSNISupport object so the per-request check only compares host vs SNI.

#### [MEDIUM] Global atomic stat counters updated on every read/write syscall bounce shared cache lines across all net threads
**`src/iocore/net/UnixNetVConnection.cc:542`** · _performance_

The metrics subsystem stores one global std::atomic<int64_t> per stat, packed adjacently in spans (include/tsutil/Metrics.h:64-68, fetch_add with memory_order_relaxed), with no per-thread or per-core sharding and no cache-line alignment. The net fast path increments net_rsb.calls_to_read on every recvmsg (line 542), read_bytes and read_bytes_count on every successful read (lines 574-575), and calls_to_write on every sendmsg iteration (line 882) — several RMWs per IO event, all threads targeting the same few cache lines, with adjacent unrelated counters false-sharing the same 64B lines. At high event rates this is a measurable cross-core coherence cost per syscall, not per request. The same pattern appears per request in remap: url_mapping::_hitCount is a std::atomic<uint64_t> incremented with default seq_cst ordering on every matched request (include/proxy/http/remap/UrlMapping.h:120,169), a single hot line when one rule dominates traffic.

```
UnixNetVConnection.cc:542: Metrics::Counter::increment(net_rsb.calls_to_read); UnixNetVConnection.cc:574-575: Metrics::Counter::increment(net_rsb.read_bytes, r); Metrics::Counter::increment(net_rsb.read_bytes_count); Metrics.h:65-68: increment(int64_t val) { _value.fetch_add(val, MEMORY_ORDER); } UrlMapping.h:167-170: incrementCount() { _hitCount++; }
```

**Fix:** Shard hot counters per event thread (each thread updates its own padded slot; readers sum on scrape, as the old RecRaw stats did), or at minimum batch per-IO counters into thread-locals flushed periodically; make _hitCount use fetch_add(1, std::memory_order_relaxed).

#### [MEDIUM] Remap host table lookup constructs a heap-allocating std::string temporary per request
**`src/proxy/http/remap/UrlRewrite.cc:314`** · _performance_

URLTable is 'std::unordered_map<std::string, UrlMappingPathIndex *>' (include/proxy/http/remap/UrlRewrite.h:63) with the default non-transparent std::hash<std::string>, and _tableLookup calls 'h_table->find(request_host)' with a char*. Every call materializes a temporary std::string from the lowercased host, which heap-allocates and frees for any hostname longer than the SSO threshold (~15 chars — common for real hostnames). _mappingLookup runs on the request path for every forward remap lookup (UrlRewrite.cc:942), so this is an avoidable malloc/free pair plus copy per proxied request; requests that also consult redirect/reverse tables pay it again.

```
UrlRewrite.cc:314: if (auto it = h_table->find(request_host); it != h_table->end()) { UrlRewrite.h:63: using URLTable = std::unordered_map<std::string, UrlMappingPathIndex *>; UrlRewrite.cc:942: url_mapping *mapping = _tableLookup(mappings.hash_lookup, request_url, request_port, request_host_lower, request_host_len);
```

**Fix:** Enable C++20 heterogeneous lookup: define a transparent hash/equal (struct with is_transparent operating on std::string_view) for URLTable and pass std::string_view{request_host_lower, request_host_len} to find(); no allocation, and the already-computed length is reused instead of strlen.

#### [MEDIUM] Remap path Trie uses 2KB 256-way nodes: one dependent cache miss per URL path character on every lookup
**`include/tscore/Trie.h:111`** · _performance_

UrlMappingPathIndex::Search (src/proxy/http/remap/UrlMappingPathIndex.cc:91) runs Trie::Search on the request path for every hash-mapped remap lookup. Each Trie node holds 'Node *children[256]' plus value/occupied/rank (~2072 bytes), and Search performs 'curr_node = curr_node->GetChild(key[i])' — a dependent pointer chase into a fresh 2KB heap block per path character until the deepest matching rule prefix. Nodes are individually ats_malloc'd (Trie.h:105), so consecutive characters have no locality: a config whose rules share a 30-character path prefix costs ~30 serialized cache misses per request, per table consulted. The layout is also memory-hostile at config scale (one 2KB node per distinct prefix character across all rules), which further guarantees the working set does not fit in cache.

```
Trie.h:76: static const int N_NODE_CHILDREN = 256; Trie.h:111: Node *children[N_NODE_CHILDREN]; Trie.h:105: child = static_cast<Node *>(ats_malloc(sizeof(Node))); Trie.h:210-211: curr_node = curr_node->GetChild(key[i]); ++i;
```

**Fix:** Replace with a compressed radix tree (path compression collapses shared prefixes to one node with an inline string compare) or swoc::IPSpace-style flat structure; even a first step of storing edges as a small sorted array instead of 256 pointers would cut node size ~60x and make the walk mostly cache-resident.

#### [LOW] Session pool acquisition computes an MD5 hash of the hostname per outbound request, with per-call EVP context allocation on no-deprecated OpenSSL builds
**`src/proxy/http/HttpSessionManager.cc:388`** · _performance_

HttpSessionManager::acquire_session runs on every transaction that attempts origin connection reuse and computes 'CryptoContext().hash_immediate(hostname_hash, ..., strlen(hostname))' — a full MD5 (or SHA256 under FIPS) of the origin hostname each time, even when the session-sharing match style is IP-only. On builds where HAVE_MD5_INIT is false (OpenSSL compiled no-deprecated / FIPS), the MD5Context constructor calls EVP_MD_CTX_new() and EVP_DigestInit_ex per invocation (include/tscore/MD5.h:44-47), adding a heap allocation and an OpenSSL algorithm fetch to the per-request path. The hostname was already hashed for HostDB and will be re-derived elsewhere; a cheap non-crypto hash (or a hash cached on the transaction) suffices for pool bucketing.

```
HttpSessionManager.cc:385-388: CryptoHash hostname_hash; ... CryptoContext().hash_immediate(hostname_hash, (unsigned char *)hostname, strlen(hostname)); MD5.h:44-47: _ctx = EVP_MD_CTX_new(); EVP_DigestInit_ex(_ctx, EVP_md5(), nullptr);
```

**Fix:** Bucket the pool by a non-cryptographic hash (e.g. wyhash/xxh3 of the lowercased host) or compute the CryptoHash once per transaction and pass it in; if MD5 must stay, keep a thread-local EVP_MD_CTX and reset it instead of allocating per call.

#### [LOW] Every log entry evaluates all format fields twice (marshal_len pass then marshal pass)
**`src/proxy/logging/LogObject.cc:645`** · _performance_

LogObject::log first calls m_format->m_field_list.marshal_len(lad) to size the entry, then marshal(lad, buf) to write it (line 683). LogField::marshal_len is documented to work 'by using the property of the marshalling routines that if the marshal buffer is NULL, only the size requirement is returned' (src/proxy/logging/LogField.cc:500-529) — i.e. the full field accessor runs twice per field per entry. For header-based fields (%<{...}cqh> etc.) this means two mime_hdr_field_find lookups per field per transaction (LogField.cc:537 calls lad->marshal_http_header_field twice), and custom formats with many fields double their entire marshal cost on the logging fast path of every request. LogAccess::init caches only a handful of URL strings (LogAccess.cc:69-96); everything else is recomputed.

```
LogObject.cc:645: bytes_needed = m_format->m_field_list.marshal_len(lad); LogObject.cc:683: bytes_used = m_format->m_field_list.marshal(lad, &(*buffer)[offset]); LogField.cc:503-505: '...if the marshal buffer is NULL, only the size requirement is returned.' LogField.cc:525: return (lad->*m_marshal_func)(nullptr);
```

**Fix:** Marshal once into a per-thread scratch buffer sized to the format's typical entry, then reserve exactly bytes_used in the LogBuffer and memcpy; or extend the marshal API to return length+data in one pass with an optional cache of looked-up MIMEField pointers on the LogAccess object.


### Code Quality & Maintainability

_Quality audit of ~297K lines of C++ across src/. Quantitative picture: the three largest files are true monoliths (src/proxy/http/HttpTransact.cc 9,430 lines; src/api/InkAPI.cc 9,274; src/proxy/http/HttpSM.cc 9,253), with individual functions of 499, 407, and 386 lines on the hot request path. Tech-debt markers total 305 (209 TODO, 33 FIXME, 40 XXX), several of which document known races and unfinished error handling rather than cosmetic gaps; there are ~226 commented-out statements, 482 goto statements in proxy+iocore, and 446 manual ats_malloc/ats_free call sites contradicting the stated RAII/smart-pointer policy (raw malloc is at least mostly confined to PCRE allocator callbacks). Preprocessor conditional density peaks at 61 in src/iocore/net/UnixUDPNet.cc and 46 in SSLUtils.cc. Error handling is inconsistent: 2,162 ink_assert/ink_release_assert sites coexist with silently swallowed failures (e.g. an H3 QPACK decode failure that is dropped with a bare break). The most alarming individual items are comments that admit real defects and leave them in place, headlined by a documented use-after-free race in log config reload._

#### [HIGH ✓verified] Documented, unfixed use-after-free race between TSTextLogObjectCreate and log config reload
**`src/proxy/logging/Log.cc:133`** · _race_

Log::change_configuration() swaps the active LogConfig and then releases the old manager's API mutex. A comment in the code itself states that a plugin calling TSTextLogObjectCreate() concurrently can register its LogObject with the old (soon-to-be-freed) LogConfig, and that Traffic Server 'would crash the next time the plugin referenced the freed object'. This is a known crash race on the config-reload path that has been shipped as an XXX comment instead of being fixed or asserted against; config reload plus API log objects is a realistic production combination.

```
// XXX There is a race condition with API objects. If TSTextLogObjectCreate()
// is called before the Log::config swap, then it will be blocked on the lock
// on the *old* LogConfig and register it's LogObject with that manager. If
// this happens, then the new TextLogObject will be immediately lost. Traffic
// Server would crash the next time the plugin referenced the freed object.
```

**Fix:** Close the window: after the ink_atomic_swap, re-check the old manager for objects registered during the race and migrate them to the new LogConfig before the old one is scheduled for deletion (the API mutex is already held, so a migration loop there is safe), or route TSTextLogObjectCreate through configProcessor's refcounted get() so it always registers against the current config.

**Verification:** Traced end-to-end. (1) TSTextLogObjectCreate (src/api/InkAPI.cc:6506-6534) reads the raw global Log::config with no refcount and calls manage_api_object, which blocks on the old manager's _APImutex (LogObject.cc:943). (2) Log::change_configuration (Log.cc:111-152) runs on the log preproc thread (Log.cc:233, invoked from the pthread loop at Log.cc:1536 — not continuation-dispatched, so EThread::process_event mutex protection does not apply), holds that same _APImutex while transfer_objects (LogConfig.cc:325, LogObject.cc:1250-1252) copies only already-registered API objects, swaps Log::config (Log.cc:131), and releases the mutex — the blocked creator then registers its object into the OLD manager's _APIobjects with refcount 1 (LogObject.cc:955-957), after the transfer. (3) configProcessor.set (Log.cc:145 → ConfigProcessor.cc:153-164) schedules deletion of the old LogConfig, whose ~LogObjectManager (LogObject.cc:922-937) refcount_dec's the orphaned API object to 0 and deletes it, while the plugin still holds the raw pointer returned at InkAPI.cc:6533. (4) TSTextLogObjectWrite's sanity check is only a null check; TSTextLogObjectDestroy would call unmanage_api_object on the NEW config and fail to find the object (LogObject.cc:1193-1207). Guards searched for and absent: no re-read of Log::config after mutex acquisition, no generation counter, no plugin-held refcount, no shared continuation mutex between the two paths. The XXX comment at Log.cc:133-137 accurately describes live behavior. Caveats: the interleaving window is narrow and the crash is deferred until the ConfigProcessor release timeout fires, so this is a genuine but low-probability-per-reload race.

#### [MEDIUM] H3 QPACK header decode failure is silently swallowed on the request path
**`src/proxy/http3/Http3HeaderVIOAdaptor.cc:97`** · _logic-bug_

Http3HeaderVIOAdaptor::event_handler() handles QPACK_EVENT_DECODE_FAILED with a debug log and a bare break, then returns EVENT_DONE. No error is propagated to the transaction or connection, so a malformed/undecodable HTTP/3 header block leaves the stream in limbo instead of resetting it or closing the connection as RFC 9204 requires. The gap is acknowledged in-code with a FIXME. This is representative of a broader inconsistency: 2,162 assert sites elsewhere, but hard failures here are ignored.

```
case QPACK_EVENT_DECODE_FAILED:
    Dbg(dbg_ctl_v_http3, "%s (%d)", "QPACK_EVENT_DECODE_FAILED", event);
    // FIXME: handle error
    break;
```

**Fix:** Propagate the failure to Http3Transaction so the stream is reset with H3_INTERNAL_ERROR / the connection closed with QPACK_DECOMPRESSION_FAILED, mirroring how the HTTP/2 path surfaces HPACK errors.

#### [MEDIUM] HttpTransact.cc is a 9,430-line monolith with a 499-line core function
**`src/proxy/http/HttpTransact.cc:4495`** · _quality_

HttpTransact.cc is the largest file in the tree (9,430 lines). handle_cache_operation_on_forward_server_response() alone is 499 lines of nested switch/if logic mutating State in place; client_result_stat() is 318 lines, HandleCacheOpenReadHit() 232, what_is_document_freshness() 206. The function-header comment blocks are empty ('Description:\n// Details :' with nothing filled in), so the only documentation of this cache-correctness-critical logic is the code itself. This concentration makes cache-behavior changes high-risk and reviews ineffective.

```
// Name       : handle_cache_operation_on_forward_server_response
// Description:
//
// Details    :
//
...
void
HttpTransact::handle_cache_operation_on_forward_server_response(State *s)
```

**Fix:** Incrementally extract per-status-code handlers (304, 5xx, 2xx) from handle_cache_operation_on_forward_server_response into named helpers with unit tests, and split HttpTransact.cc along its existing sections (cache decision, freshness, stats, response building) into separate translation units.

#### [MEDIUM] HttpSM god-functions: 407-line do_http_server_open and 386-line, 71-case set_next_state
**`src/proxy/http/HttpSM.cc:5670`** · _quality_

HttpSM.cc (9,253 lines) concentrates connection setup and state dispatch into single enormous functions. do_http_server_open(bool raw, bool only_direct) (line 5670) is 407 lines mixing plugin tunnels, ip_allow filtering, self-loop detection, session-pool reuse, auth-driven private sessions, and connection tracking; set_next_state() (line 8281) is a 386-line switch over 71 StateMachineAction_t cases. Boolean-parameter entry points and a mega-switch dispatcher are the classic god-class signature; every new feature (e.g. connection tracking, probes) has been spliced into these same bodies, and inline commentary admits behavioral uncertainty ('It appears that we can now set the next_action to error... presumably due to a plugin').

```
void
HttpSM::do_http_server_open(bool raw, bool only_direct)  // 407 lines
...
HttpSM::set_next_state()  // 386 lines, 71 'case HttpTransact::StateMachineAction_t' labels
```

**Fix:** Split do_http_server_open into phases (precondition checks, session reuse lookup, new-connection setup) as private member functions; replace the raw/only_direct bool pair with an enum. Consider a table of StateMachineAction_t -> member-function-pointer to dismantle set_next_state.

#### [MEDIUM] InkAPI.cc: 9,274-line API god-file with 24 copies of a stale changelog comment
**`src/api/InkAPI.cc:895`** · _quality_

InkAPI.cc implements ~793 top-level functions (the entire C plugin API surface: mbuffers, URLs, MIME, HTTP txn/ssn, cache, net, config, stats) in one 9,274-line file with 637 sdk_assert sites. Copy-paste maintenance is visible in the same historical comment ('Changed the return value of function from void to TSReturnCode.') pasted verbatim 24 times (lines 895, 1477, 1526, ...). In TSMBufferDestroy the isWriteable(bufp) check even runs before the sdk_sanity_check_mbuffer assert, i.e. the pointer is dereferenced before it is validated - a pattern the copy-paste replication has spread.

```
// Allow to modify the buffer only
  // if bufp is modifiable. If bufp is not modifiable return
  // TS_ERROR. If allowed, return TS_SUCCESS. Changed the
  // return value of function from void to TSReturnCode.
  if (!isWriteable(bufp)) {
    return TS_ERROR;
  }
  sdk_assert(sdk_sanity_check_mbuffer(bufp) == TS_SUCCESS);   [24 occurrences of the comment]
```

**Fix:** Split InkAPI.cc by API domain (InkAPIHdr.cc, InkAPITxn.cc, InkAPICache.cc, ...), delete the 24 stale changelog comments, and audit the sanity-check-before-use ordering while moving each function.

#### [MEDIUM] HTTPHdr-to-MIOBuffer serialization loop duplicated across HTTP/1, HTTP/2, and HTTP/3 stacks
**`src/proxy/http3/Http3HeaderVIOAdaptor.cc:135`** · _quality_

The dumpoffset/bufindex/block do-while loop that serializes an HTTPHdr into an MIOBuffer exists three times: HttpSM::write_header_into_buffer (src/proxy/http/HttpSM.cc:6910), Http2Stream.cc:331 ('Borrowing logic from HttpSM::write_header_into_buffer'), and Http3HeaderVIOAdaptor::_on_qpack_decode_complete. The H3 copy carries a TODO enumerating three ways to deduplicate it, so the debt is self-acknowledged. Any fix to the loop (e.g. block-allocation edge cases) must now be applied in three protocol stacks or they silently diverge.

```
// TODO: Http2Stream::send_request has same logic. It originally comes from HttpSM::write_header_into_buffer.
// a). Make HttpSM::write_header_into_buffer static
//   or
// b). Add interface to HTTPHdr to dump data
...
do {
    bufindex = 0;
    tmp      = dumpoffset;
    block    = writer->get_current_block();
```

**Fix:** Implement option (b) from the TODO: add HTTPHdr::write_into(MIOBuffer &) (or a free function in proxy/hdrs) and delete the three hand-rolled loops.

#### [MEDIUM] create_volume: self-declared 'really bad code' with a function-local static that breaks reinitialization
**`src/iocore/cache/CacheProcessor.cc:1335`** · _logic-bug_

create_volume() opens with the maintainer note 'This is some really bad code, and needs to be rewritten!' and immediately uses 'static int curr_vol = 0' flagged '// FIXME: this will not reinitialize correctly'. Because the round-robin cursor persists across invocations/reconfigurations, volume placement after a cache volume reconfiguration depends on stale state from the previous configuration pass - a latent correctness bug in cache stripe assignment, in addition to being non-reentrant.

```
// This is some really bad code, and needs to be rewritten!
int
create_volume(int volume_number, off_t size_in_blocks, CacheType scheme, CacheVol *cp)
{
  static int curr_vol       = 0; // FIXME: this will not reinitialize correctly
```

**Fix:** Move curr_vol into the configuration-pass context (e.g. a parameter or a member of the object driving volume creation) so each (re)configuration starts from a defined cursor, then schedule the promised rewrite.

#### [LOW] Raw malloc without null-check in OCSP prefetch path, contradicting stated memory policy
**`src/iocore/net/OCSPStapling.cc:906`** · _quality_

stapling_refresh_response() uses bare malloc/free (the project policy mandates ats_malloc, which aborts on OOM, or RAII) and never checks the malloc result before fread(rsp_buf, 1, rsp_buf_len, fp): a failed allocation (e.g. an unexpectedly huge prefetched response file, since rsp_buf_len comes straight from ftell) dereferences nullptr. It also mallocs 0 bytes when the file is empty. This is one of the few genuine raw-malloc call sites outside PCRE allocator callbacks (tsutil/Regex.cc, cripts/Matcher.cc); the file otherwise uses ats_strdup/unique_ptr, so the inconsistency is local and easy to fix.

```
long rsp_buf_len = ftell(fp);
if (rsp_buf_len >= 0) {
  rewind(fp);
  unsigned char *rsp_buf  = static_cast<unsigned char *>(malloc(rsp_buf_len));
  auto           read_len = fread(rsp_buf, 1, rsp_buf_len, fp);
```

**Fix:** Use ats_malloc (or std::vector<unsigned char>/ats_scoped_mem) and reject empty or implausibly large files before reading; this removes both the null-deref path and the policy violation.


### Test Coverage & Documentation Health

_Test and documentation health is uneven: infrastructure code (cache: 27 unit-test files; hdrs, eventsystem, net config parsing) is well covered, but the proxy's core request path — HttpSM (9253 lines, zero unit tests) and HttpTransact (9430 lines, one TEST_CASE covering a single helper) — relies entirely on end-to-end autests, which themselves lean on wall-clock sleeps (109 'sleep N' steps, 33 time.sleep calls) and carry 8 permanently skipped tests including the only log-retention coverage. Documentation has measurable drift from src/records/RecordsConfig.cc: 3 wrong documented defaults, 4 documented-but-unregistered parent-proxy records (one with a default that contradicts the code's fallback), and 49 registered records documented nowhere. The checked-in ci/ tree is dead weight — every ci/jenkins script drives an autotools build that cannot build the CMake-only master, ci/coverage and ci/regression are empty, and the developer-guide CI page is an empty heading, so sanitizer coverage (ASAN/TSAN/LSAN presets exist in CMakePresets.json) is not verifiable from the repository._

#### [HIGH] HttpSM/HttpTransact (~19k lines of core request-path logic) have essentially no unit test coverage
**`src/proxy/http/unit_tests/test_HttpTransact.cc:40`** · _testing_

HttpSM.cc (9253 lines) has zero unit tests anywhere in the tree; the only files under src/proxy/http/unit_tests are test_ChunkedHandler.cc, test_ForwardedConfig.cc, test_HttpTransact.cc, test_HttpTransactHeaders.cc, test_HttpUserAgent.cc, test_PreWarm.cc, and test_error_page_selection.cc. HttpTransact.cc (9430 lines — freshness/caching decisions, retry logic, redirect following) is covered by a single Catch2 TEST_CASE that exercises only merge_response_header_with_cached_header plus a null-remap-table check. The legacy RegressionHttpTransact.cc is 146 lines covering two trivial helpers (is_request_valid, handle_trace_and_options_requests) and runs only via the old in-binary 'traffic_server -R' framework. HttpTunnel.cc (2185 lines), HttpCacheSM.cc, Http1ClientSession/ServerSession also have no unit tests. By contrast, the cache has 27 dedicated unit-test files (src/iocore/cache/unit_tests). All confidence in the hottest decision logic in the proxy rests on end-to-end autests, which cannot exercise most HttpTransact branch combinations (cache-hit-stale + parent-down + redirect, etc.), so refactors of this code land with no fast safety net.

```
src/proxy/http/unit_tests/test_HttpTransact.cc:40 'TEST_CASE("HttpTransact", "[http]")' — the file's only TEST_CASE, containing SECTION("RemapProcessor tolerates a missing remap table") and SECTION("HttpTransact::merge_response_header_with_cached_header"). wc -l: 973 test_HttpTransact.cc vs 9430 HttpTransact.cc, 9253 HttpSM.cc.
```

**Fix:** Extract the pure decision functions in HttpTransact (what_is_document_freshness, HandleCacheOpenReadHit paths, retry/redirect policy) behind testable seams and grow test_HttpTransact.cc around them; port the two RegressionHttpTransact.cc checks to Catch2 and delete the legacy file. Even table-driven tests of freshness/CC directive handling would cover the highest-risk logic.

#### [MEDIUM] In-repo CI (ci/jenkins) is entirely autotools-based and cannot build master; CI developer doc is an empty page
**`ci/jenkins/bin/build.sh:47`** · _testing_

Every script in ci/jenkins/bin drives an autotools build (autoreconf/./configure/make), but the repo has been CMake-only since v10 — there is no configure.ac or configure script in the tree, so build.sh, autest.sh, regression.sh, in_tree.sh, out_of_tree.sh, cache-tests.sh, coverity.sh, clang-analyzer.sh, docs.sh and github.sh all fail immediately against master. ci/jenkins/jobs.yaml likewise invokes '${WORKSPACE}/src/configure ... --enable-werror' (line 51). ci/coverage/ and ci/regression/ are empty directories. The only sanitizer reference in ci/ is the env-gated '--enable-asan' in this dead script (ASAN/TSAN/LSAN presets exist in CMakePresets.json — branch-asan/branch-lsan/branch-tsan — but nothing in-repo shows which jobs actually run them). Meanwhile doc/developer-guide/continuous-integration/index.en.rst is 24 lines containing only the heading 'Continuous Integration' and no body. Contributors reading the repo cannot determine what CI runs, and the checked-in scripts actively mislead.

```
ci/jenkins/bin/build.sh:47 '../configure \' (with line 33 '[ "1" == "$enable_asan" ] && ASAN="--enable-asan"'); ci/jenkins/jobs.yaml:51 '"${WORKSPACE}"/src/configure --prefix=...'; ci/jenkins/bin/autest.sh:86-87 'autoreconf -if / ./configure'; doc/developer-guide/continuous-integration/index.en.rst ends at line 24 with only the section title.
```

**Fix:** Either update ci/jenkins to the CMake presets the real Jenkins uses (or point at the external CI repo and delete the dead scripts and empty ci/coverage, ci/regression dirs), and write the continuous-integration developer page documenting which jobs run ASAN/TSAN/LSAN and autests per PR.

#### [MEDIUM] records.yaml.en.rst documents three registered config defaults that contradict RecordsConfig.cc
**`doc/admin-guide/files/records.yaml.en.rst:4087`** · _docs_

A systematic diff of ts:cv INT defaults in doc/admin-guide/files/records.yaml.en.rst against RecordsConfig.cc finds three wrong documented defaults: proxy.config.diags.logfile.rolling_size_mb documented as 100 (doc line 4087) but registered as "10" (RecordsConfig.cc:261); proxy.config.net.sock_notsent_lowat documented as 16384 (doc line 5869) but registered as "32768" (RecordsConfig.cc:821); proxy.config.io_uring.entries documented as 32 (doc line 6075) but registered as "1024" (RecordsConfig.cc:1565). Operators sizing diag-log rotation or tuning TCP_NOTSENT_LOWAT from the docs will reason from values 10x/2x/32x off from what the server actually uses.

```
doc line 4087: '.. ts:cv:: CONFIG proxy.config.diags.logfile.rolling_size_mb INT 100' vs src/records/RecordsConfig.cc:261 '{RECT_CONFIG, "proxy.config.diags.logfile.rolling_size_mb", RECD_INT, "10", ...}'; doc 5869 'sock_notsent_lowat INT 16384' vs RecordsConfig.cc:821 '"32768"'; doc 6075 'io_uring.entries INT 32' vs RecordsConfig.cc:1565 '"1024"'.
```

**Fix:** Fix the three doc defaults, and add a CI check (docs build step) that parses ts:cv defaults out of records.yaml.en.rst and compares them to RecordsConfig.cc so drift fails the docs job.

#### [MEDIUM] Parent-proxy records documented as ts:cv are not registered in RecordsConfig.cc; documented default for max_trans_retries (2) differs from code fallback (0)
**`doc/admin-guide/files/records.yaml.en.rst:1539`** · _docs_

proxy.config.http.parent_proxy.max_trans_retries (doc line 1539, 'INT 2'), consistent_hash_replicas (doc line 1650, 'INT 1024'), consistent_hash_seed0 and consistent_hash_seed1 are all documented as normal CONFIG records, but none appears in src/records/RecordsConfig.cc. Because they are unregistered, setting them in records.yaml triggers RecConfigWarnIfUnregistered's "Unrecognized configuration value" warning (src/records/RecCore.cc:1089). Worse, the code default disagrees with the documented default: include/proxy/ParentSelection.h:382 reads the record with .value_or(0), so when unset, max_retriers is 0 — not the documented 2 — meaning parent retry limiting is effectively disabled by default while the docs claim 2.

```
doc/admin-guide/files/records.yaml.en.rst:1539 '.. ts:cv:: CONFIG proxy.config.http.parent_proxy.max_trans_retries INT 2'; include/proxy/ParentSelection.h:382 'ParentSelectionStrategy() { max_retriers = RecGetRecordInt("proxy.config.http.parent_proxy.max_trans_retries").value_or(0); }'; grep of RecordsConfig.cc for parent_proxy shows no registration for max_trans_retries, consistent_hash_replicas, consistent_hash_seed0/1 (only file, retry_time, fail_threshold, etc. at lines 444-464).
```

**Fix:** Register the four records in RecordsConfig.cc with the documented defaults (max_trans_retries=2, consistent_hash_replicas=1024, seeds=0), or correct the docs to state the real default (0) and note the records are read-but-unregistered.

#### [MEDIUM] 49 registered configuration records are documented nowhere under doc/
**`src/records/RecordsConfig.cc:1313`** · _docs_

Comparing all RECT_CONFIG names in src/records/RecordsConfig.cc (562 unique) against every file under doc/ finds 49 registered records with zero documentation anywhere, including security-relevant proxy.config.plugin.load_elevated (RecordsConfig.cc:1313, RECA_READ_ONLY), operational knobs like proxy.config.http.per_server.connection.metric_enabled/metric_prefix, proxy.config.cache.ram_cache.compress_percent, proxy.config.hostdb.migrate_on_demand, proxy.config.http.referer_filter/referer_default_redirect/referer_format_redirect (RecordsConfig.cc:429), and the whole HTTP/3 tuning family (proxy.config.http3.header_table_size, max_field_section_size, max_settings, qpack_blocked_streams at RecordsConfig.cc:1422, num_placeholders). Users cannot discover or safely tune any of these; several (e.g. the http3 group) are for a headline v10 feature.

```
src/records/RecordsConfig.cc:1313 '{RECT_CONFIG, "proxy.config.plugin.load_elevated", RECD_INT, "0", RECU_RESTART_TS, RR_NULL, RECC_INT, "[0-1]", RECA_READ_ONLY}' — 'grep -r proxy.config.plugin.load_elevated doc/' returns nothing; same for 48 others (full list generated by comm(1) diff of extracted names, e.g. proxy.config.http3.qpack_blocked_streams at RecordsConfig.cc:1422).
```

**Fix:** Triage the 49-record list: document the intentionally supported ones in records.yaml.en.rst, and delete truly dead registrations (e.g. proxy.config.http.parent_proxies, proxy.config.http.enable_http_stats if unused). Add the same doc-vs-RecordsConfig CI cross-check suggested above to keep the sets in sync.

#### [MEDIUM] Widespread sleep-based synchronization in autests (109 'sleep N' steps, 33 time.sleep calls) invites timing flakiness
**`tests/gold_tests/pluginTest/traffic_dump/traffic_dump.test.py:359`** · _testing_

gold_tests contains 109 'sleep N' shell-command test steps in .test.py files plus 33 time.sleep() calls in Python helpers, many of which gate assertions on wall-clock guesses rather than events. traffic_dump.test.py is representative: after 'traffic_ctl plugin msg traffic_dump.limit 0' it runs a test step whose Command is literally 'sleep 2' (line 343, comment 'Give ATS some time to process the change') and later 'sleep 2' at line 359 followed immediately by 'file.Exists = False' for the expected-absent dump file — a negative assertion that passes vacuously if the plugin is merely slow, and six such sleep-2 steps exist in this one file (lines 343-426). Other examples: block_errors.test.py uses six 'sleep 30' watcher processes; slice_prefetch.test.py:138 prefixes a curl with 'sleep 5'; stek_share.test.py:293 'sleep 10 && curl'. One test has already been permanently disabled for exactly this failure mode (see log_retention finding).

```
traffic_dump.test.py:358-362: '# Sleep 2 seconds to give the replay plugin plenty of time to write the file.' / 'tr.Processes.Default.Command = "sleep 2"' / 'file = tr.Disk.File(replay_file_session_12)' / 'file.Exists = False'. Counts: grep for sleep in *.test.py = 109 lines; time.sleep in tests/gold_tests/**/*.py = 33.
```

**Fix:** Replace timing sleeps with condition polling: autest Ready conditions, Condition-based file/log waiting (ATS already has 'await' log-watch patterns), or traffic_ctl polling loops with deadline. Add an autest lint (tests/CI) flagging bare 'sleep' commands in new tests.

#### [MEDIUM] Eight autests are permanently skipped via Condition.true, leaving log rotation and other features with zero CI coverage
**`tests/gold_tests/logging/log_retention.test.py:31`** · _testing_

Eight gold tests are unconditionally disabled with Test.SkipIf(Condition.true(...)): logging/log_retention.test.py:31 ('sensitive to timing issues which makes it flaky' — meaning log space retention/rotation enforcement has no end-to-end coverage at all), three txn_box tests ('This needs to be revisit. TS not finishing up gracefully.'), traffic_dump_http3.test.py:31 ('until the TS_EVENT_HTTP_SSN are supported for QUIC connections'), post_slow_server.test.py:25 and config_destroy_thread.test.py:29 ('takes too long to run in CI'), and timeout/conn_timeout.test.py:23 ('requires privilege'). None has a tracking mechanism; these silently rot while appearing to exist as coverage. The log_retention case is the most concerning since proxy.config.log.max_space_mb_* enforcement is a disk-filling failure mode in production.

```
tests/gold_tests/logging/log_retention.test.py:27-31: '# This test is sensitive to timing issues... make it generally skipped when the suite of AuTests are run' / 'Test.SkipIf(Condition.true("This test is sensitive to timing issues which makes it flaky."))'. grep 'SkipIf(Condition.true' lists 8 files including txn_box_txn-error.test.py:26, traffic_dump_http3.test.py:31, post_slow_server.test.py:25, conn_timeout.test.py:23.
```

**Fix:** File tracking issues for each skip and reference them in the skip message; rewrite log_retention with event-driven waits (it is the poster child for the sleep-flakiness finding) so retention enforcement regains coverage; move 'too slow for CI' tests to a nightly/extended autest tier instead of skipping outright.

#### [LOW] No developer documentation exists for HttpSM/HttpTransact, the subsystem CLAUDE/README point newcomers at
**`doc/developer-guide/core-architecture/index.en.rst:1`** · _docs_

doc/developer-guide/core-architecture/ contains only heap.en.rst, hostdb.en.rst, and url_rewrite_architecture.en.rst (plus HostDB diagrams). There is no architecture document for the HTTP state machine (HttpSM), HttpTransact decision engine, HttpTunnel, or session management — the code every contributor must touch first; grep of doc/developer-guide for 'HttpSM|HttpTransact' finds only passing mentions in hostdb.en.rst, tracing.en.rst, cache architecture, client-session-architecture, and plugins/introduction. The cache, by comparison, has a full cache-architecture/ chapter. Combined with the near-zero unit coverage of the same files (finding 1), the project's most complex subsystem has neither tests nor prose to defend its invariants.

```
ls doc/developer-guide/core-architecture: 'heap.en.rst hostdb.en.rst index.en.rst url_rewrite_architecture.en.rst HostDB-Data-Layout.png HostDB-Data-Layout.svg'; grep -rli 'HttpSM|HttpTransact' doc/developer-guide returns only 5 files, none an HttpSM/HttpTransact document.
```

**Fix:** Add a core-architecture/http-state-machine.en.rst covering the HttpSM event/handler model, HttpTransact state table, tunnel setup, and cache SM interaction — even a state-diagram plus handler-naming conventions would materially lower the contribution barrier.

