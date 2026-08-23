# Apache Traffic Server 10.2.1 — Codebase Audit

_Branch `10.2.x` at commit `31f1f2f3b` (project version 10.2.1). Multi-lens static review; every critical/high memory-safety, race, and overflow claim was re-verified by an adversarial agent that tried to refute it._

## Scope & method

Twelve specialized reviewers read the 10.2.1 tree (~371k lines of C++20) with grep/read before reporting. Critical/high memory-safety, race, and overflow claims were then handed to a separate verifier instructed to disprove them. This is an independent re-audit of the release branch, not a remap of the `master` audit — line numbers and the finding set differ.

## Headline

- **2 critical**, **7 high**, **22 medium**, **18 low** (49 findings).
- The **HTTP/3 QPACK decoder** carries the critical bug and most confirmed memory-safety defects — attacker-facing whenever HTTP/3 is enabled.
- **Several confirmed 10.2.1 findings already have fixes on the `master`-based branch `claude/codebase-audit-review-9nw7vz`** and only need backporting (marked below). The plugin-api reviewer independently noted these "have fixes in the development tree that were never carried into this 10.2 release branch."
- Caveat: the **SSL blind-tunnel UAF** (fixed on master as #16) was **refuted** on 10.2.1 — the verifier found the `ProtocolProbeSessionAccept` endpoint is always non-null there, structurally guarding the synchronous-close path. Confirm before backporting #16.

## Confirmed memory-safety / concurrency bugs (verified)

| Sev | Bug | Location | Fix status |
|-----|-----|----------|-----------|
| critical | QPACK static-table lookup by index has no bounds check (remote OOB read on HTTP/3 header decode) | `src/proxy/http3/QPACK.cc:1219` | master #63 (static-table bounds + is_static) |
| critical | QPACK static-table lookup has no bounds check: OOB read from wire-controlled index | `src/proxy/http3/QPACK.cc:1222` | master #63 (static-table bounds + is_static) |
| high | QPACK 'Insert With Name Reference' ignores the S (static) flag and never bounds-checks the index | `src/proxy/http3/QPACK.cc:1156` | master #63 (honor is_static) |
| high | QPACK integer/string decode errors are swallowed by '&&' instead of '||', causing uninitialized reads and pointer underflow | `src/proxy/http3/QPACK.cc:923` | master #19/#20 (&& -> ||) |
| high | Data race: remap plugin context save/restore uses a shared member instead of a stack local | `src/proxy/http/remap/RemapPluginInfo.cc:278` | master #30 (stack-local context) |

---
## Findings by area

### Network Core & Event-System Lifetime  (1 high, 1 medium)

_The network core and event-system lifetime handling in ats-10.2.1 is largely robust: do_io_close's recursion/close_inline gating, the cross-thread `closed` handshake, and the recently-hardened async_ep eventfd teardown (now covered by a unit test) all correctly avoid freeing a VC out from under pending callbacks. The two issues worth a maintainer's attention are reentrancy hazards where a signal/callback can free or reconfigure an object that the caller keeps touching: (1) the SSL blind-tunnel branch of net_read_io ignores readSignalDone()'s result and dereferences `this` afterward, and the trampoline it invokes can synchronously do_io_close()/do_io_read() the VC; (2) NetHandler::manage_active_queue / manage_keep_alive_queue iterate with a cached next pointer across _close_ne() callbacks that can free other same-thread queued VCs. Both are latent (require specific continuation behavior) rather than trivially triggerable, but both are real gaps versus the defensive patterns used elsewhere in the same files._

#### [high] Blind-tunnel path in SSLNetVConnection::net_read_io dereferences `this` after readSignalDone() may free/reconfigure the VC
**`src/iocore/net/SSLNetVConnection.cc:557`** · _use-after-free_ · **refuted** · _fix available: master #16 (but REFUTED on 10.2 — verify first)_

In the SNI-decided blind-tunnel branch, net_read_io() calls `this->readSignalDone(VC_EVENT_READ_COMPLETE, nh)` and then unconditionally dereferences `this` (getSSLHandShakeComplete(), this->read, this->handShakeHolder, this->free_handshake_buffers(), and a second readSignalDone). readSignalDone() -> read_signal_done() -> read_signal_and_update() invokes the read VIO continuation, which during handshake is SSLNextProtocolTrampoline. Its ioCompletionEvent() VC_EVENT_READ_COMPLETE handler (SSLNextProtocolAccept.cc:97-131) can synchronously call `netvc->do_io_close()` when no endpoint continuation is resolved (line 129), and in the common path calls `netvc->do_io_read(endpoint_cont, 0, nullptr)` which clears read.vio.buffer. Because net_read_io runs at recursion==0, a do_io_close() inside that callback is not closed inline but read_signal_and_update() then frees the VC via nh->free_netevent() as recursion returns to 0 (returning EVENT_DONE, which this call site ignores). The subsequent `this->...` accesses are then a use-after-free; in the non-close path, `buf.writer()` at line 570 can be null after the trampoline's do_io_read cleared the buffer, giving a null dereference. Every other reentrant signal in this same function (e.g. readSignalAndUpdate at line 666, readSignalDone at 628, 581) either checks the return or returns immediately; only this site both ignores the result and keeps touching the object. Verdict: PLAUSIBLE — the free is concretely reachable via the no-endpoint branch; confirming the exact continuation state at this point (whether the trampoline is still the read cont for the SNI-tunnel case) would pin the severity.

```
this->readSignalDone(VC_EVENT_READ_COMPLETE, nh);

// If the handshake isn't set yet, ...
if (!this->getSSLHandShakeComplete()) {
  this->sslHandshakeStatus = SSLHandshakeStatus::SSL_HANDSHAKE_DONE;
  NetState          *s    = &this->read;
  MIOBufferAccessor &buf  = s->vio.buffer;
  int64_t            r    = buf.writer()->write(this->handShakeHolder);
```

**Fix:** Capture the return of the first readSignalDone() and return immediately on EVENT_DONE (as the other call sites do), or re-check `closed`/vc validity before touching `this` and `buf.writer()`. The trampoline's do_io_close()/do_io_read() paths make the post-signal object state unsafe to assume.

**Refuted:** At line 557 the read cont is SSLNextProtocolTrampoline, and net_read_io runs at recursion==0, so a synchronous close would free the VC. But no synchronous close occurs on this path. (1) The no-endpoint do_io_close at SSLNextProtocolAccept.cc:129 is unreachable: endpoint_cont = netvc->endpoint() ?: npnParent->endpoint (SSLNextProtocolAccept.cc:114-118), and npnParent->endpoint is the ProtocolProbeSessionAccept `probe` constructed non-null at HttpProxyServerMain.cc:197 and passed to SSLNextProtocolAccept at :215. Since getSSLHandShakeComplete()==false at line 563, no ALPN was negotiated so npnEndpoint is null and endpoint_cont always resolves to the non-null probe. (2) The trampoline's endpoint branch calls do_io_read(probe,0,nullptr) then send_plugin_event(probe, NET_EVENT_ACCEPT) which runs ProtocolProbeSessionAccept::mainEvent synchronously. There read.vio.get_writer()==null (just cleared) and the fresh reader has no data (client-hello still in handShakeHolder, copied only later at line 570), so mainEvent takes the ASYNC branch at ProtocolProbeSessionAccept.cc:205 (do_io_read(trampoline, BUFFER_SIZE, probe->iobuf); reenable) and does NOT synchronously invoke ProtocolProbeTrampoline::ioCompletionEvent (the only place do_io_close at :170 lives). Therefore closed is never set: read_signal_and_update (UnixNetVConnection.cc:105-108) decrements recursion to 0 with closed==0, returns EVENT_CONT, never calls free_netevent — `this` stays valid, refuting the UAF. And read.vio.buffer was re-pointed to the real probe->iobuf at ProtocolProbeSessionAccept.cc:205, so buf.writer() at line 570 is non-null, refuting the null-deref. The second signal at line 581 is immediately followed by return (line 584) with no further `this` access, so it is safe even if it frees. The claim's severity hinged explicitly on the no-endpoint branch, which is structurally guarded by the always-non-null probe.

#### [medium] NetHandler queue-management loops walk a cached next pointer while _close_ne() runs VC callbacks that can free queue entries
**`src/iocore/net/NetHandler.cc:428`** · _use-after-free_

manage_active_queue() (and identically manage_keep_alive_queue() at 482-490) iterate with `ne_next = ne->active_queue_link.next` cached before calling _close_ne(ne,...). _close_ne() invokes `ne->callback(VC_EVENT_INACTIVITY_TIMEOUT/ACTIVE_TIMEOUT, &event)`, i.e. UnixNetVConnection::mainEvent -> read/write_signal_and_update -> the state machine (HttpSM/Http2). While the NetHandler mutex is held, a state machine reacting to the timeout can synchronously do_io_close() another VC on this same thread; that close runs close_inline (recursion==0, nh mutex held) -> free_netevent -> stopCop -> remove_from_active_queue/remove_from_keep_alive_queue, freeing that VC. If the freed VC is the cached `ne_next`, the next loop iteration dereferences freed memory (`ne = ne_next; ne_next = ne->active_queue_link.next`). InactivityCop::check_inactivity deliberately drains via `cop_list.pop()` with the comment "Use pop() to catch any closes caused by callbacks," showing the authors know callbacks free entries, yet these two queue walks still use a cached-next iterator. Verdict: PLAUSIBLE — reachable only when a timeout callback closes a *different* same-thread queued VC (e.g. HTTP/2 or cross-session teardown); normal single-session timeouts free only the current `ne`, which is already accounted for.

```
NetEvent *ne               = active_queue.head;
NetEvent *ne_next          = nullptr;
...
for (; ne != nullptr; ne = ne_next) {
  ne_next = ne->active_queue_link.next;
  ...
  if ((ne->next_inactivity_timeout_at && ne->next_inactivity_timeout_at <= now) || ...) {
    _close_ne(ne, now, handle_event, closed, total_idle_time, total_idle_count);
  }
```

**Fix:** Make these loops resilient to callback-driven frees the way check_inactivity is: re-fetch from the queue head after each _close_ne, or snapshot the entries to close first and only invoke callbacks after the walk, rather than trusting a next pointer captured before running arbitrary state-machine code.


### HTTP/2 & HTTP/3 (QPACK / HPACK)  (1 critical, 2 high, 1 medium, 1 low)

_The HTTP/2 side (Http2ConnectionState.cc) is comparatively well-hardened: flow-control window updates are bounds-checked against HTTP2_MAX_WINDOW_SIZE, negative local rwnd is detected, and defensive per-minute limits exist for RST_STREAM (rapid-reset), CONTINUATION, PING, PRIORITY, SETTINGS and empty frames. The serious problems are concentrated in HTTP/3 QPACK decode. Most critically, QPACK::StaticTable::lookup(index,...) performs no bounds check on a peer-controlled index into a 99-entry table, giving a remotely triggerable out-of-bounds read on every HTTP/3 header decode (the HPACK path bounds-checks the equivalent operation, so this is a QPACK-specific regression). Compounding it, the 'Insert With Name Reference' encoder-stream handler ignores the decoded S flag and always uses the static table, and a pervasive `&&`-instead-of-`||` error-check idiom swallows decode failures, leading to uninitialized reads and pointer/length underflow in _decode_header. All findings cite confirmed code; HTTP/3 must be built/enabled (Quiche) for the request-path QPACK bugs to be reachable._

#### [critical] QPACK static-table lookup by index has no bounds check (remote OOB read on HTTP/3 header decode)
**`src/proxy/http3/QPACK.cc:1219`** · _memory-bug_ · **confirmed** · _fix available: master #63 (static-table bounds + is_static)_

QPACK::StaticTable::lookup(uint16_t index, ...) indexes STATIC_HEADER_FIELDS[index] with zero bounds checking. The QPACK static table has exactly 99 entries (indices 0-98), but the index is a peer-controlled QPACK integer decoded straight off the wire and passed in unchecked. Any index >= 99 reads a Header{const char*name; const char*value; size_t name_len; size_t value_len;} out of bounds; the garbage name/value pointers and lengths are then handed to _attach_header(), which builds std::string_view{name,name_len} and memcpy's into the header heap -> crash or heap memory disclosure. Unlike the HPACK path (HpackIndexingTable::get_header_field, src/proxy/http2/HPACK.cc:340, which explicitly rejects out-of-range indices), QPACK performs no validation. Reachable from every HTTP/3 request: decode()->_decode()->_decode_header() dispatches to _decode_indexed_header_field (static branch StaticTable::lookup(index,...) at line 709, index from xpack_decode_integer prefix 6) and _decode_literal_header_field_with_name_ref (static branch at line 756, prefix 4), and also from the peer encoder-stream handler at line 1156. None validate index < countof(STATIC_HEADER_FIELDS).

```
const XpackLookupResult
QPACK::StaticTable::lookup(uint16_t index, const char **name, size_t *name_len, const char **value, size_t *value_len)
{
  const Header &header = STATIC_HEADER_FIELDS[index];   // no check that index < 99
  *name = header.name; *name_len = header.name_len; ...
  return {index, XpackLookupResult::MatchType::EXACT};
}
```

**Fix:** Bounds-check index against countof(STATIC_HEADER_FIELDS) in StaticTable::lookup(index,...) and return MatchType::NONE when out of range; make all three call sites (lines 709, 756, 1156) treat NONE as a QPACK decompression/connection error.

**Verification:** QPACK.cc:1222 reads STATIC_HEADER_FIELDS[index] with no bounds check; the table has exactly 99 entries (array closes at line 140, I counted 99). index is peer-controlled: _decode_indexed_header_field (line 690) decodes it via xpack_decode_integer prefix-6 into a uint64_t and passes it unchecked to StaticTable::lookup at line 709 for the static-table branch (buf[0]&0x40); same for _decode_literal_header_field_with_name_ref (line 756, prefix 4) and _on_encoder_stream_read_ready (line 1156, index from _read_insert_with_name_ref which sets index=tmp up to 0xFFFF). Prefix-6 QPACK integers support multi-byte continuation, so index>=99 is trivially reachable. The static lookup ALWAYS returns MatchType::EXACT, so the `if (result.match_type != EXACT) return -1` guard at line 714 never rejects an out-of-range index. The garbage name/value pointers and lengths from the OOB Header struct are then handed to _attach_header, which builds std::string_view{name,name_len} and value_set memcpy's into the header heap -> crash or heap memory disclosure. HPACK's equivalent (HPACK.cc:340) explicitly checks index<TS_HPACK_STATIC_TABLE_ENTRY_NUM before indexing STATIC_TABLE; QPACK has no analogous check anywhere upstream (_decode_header dispatch at line ~910 does no index gating for the static branch). This is a plain missing-bounds-check OOB read on HTTP/3 header decode, not a race or lifetime issue, so the EThread mutex-at-dispatch guard is irrelevant. Failure traced end-to-end and confirmed.</parameter>
</invoke>


#### [high] QPACK 'Insert With Name Reference' ignores the S (static) flag and never bounds-checks the index
**`src/proxy/http3/QPACK.cc:1156`** · _logic-bug_ · **confirmed** · _fix available: master #63 (honor is_static)_

In _on_encoder_stream_read_ready, the 'Insert With Name Reference' instruction decodes the S flag into is_static (via _read_insert_with_name_ref, which sets is_static = input[0] & 0x40 at line 1511) but the caller then ALWAYS calls StaticTable::lookup(index, ...) regardless of is_static. Per RFC 9204 4.3.2, S=0 means the name reference is a DYNAMIC-table relative index. Two consequences: (1) correctness -- when the peer legitimately references a dynamic-table name, the decoder inserts an entry with the wrong (static-table) name, desynchronizing the decoder's dynamic table from the peer's encoder, which corrupts or fails all subsequent dynamic references on the connection; (2) safety -- index is a peer-controlled unbounded QPACK integer and StaticTable::lookup does no bounds check (see the critical finding), so a dynamic-ref insert with index >= 99 is an out-of-bounds read. The is_static variable is computed and then discarded.

```
if (this->_read_insert_with_name_ref(reader, is_static, index, this->_arena, &value, value_len) < 0) { ... }
...
StaticTable::lookup(index, &name, &name_len, &dummy, &dummy_len);   // is_static ignored; always static table
this->_dynamic_table.insert_entry(name, name_len, value, value_len);
```

**Fix:** Branch on is_static: when true use StaticTable::lookup, when false use _dynamic_table.lookup(_calc_absolute_index_from_relative_index(...)). Treat a failed/out-of-range lookup as a connection error.

**Verification:** At src/proxy/http3/QPACK.cc:1149 the 'Insert With Name Reference' branch decodes is_static (set at line 1509, input[0] & 0x40) but line 1156 unconditionally calls StaticTable::lookup(index, ...) with no branch on is_static — the flag is only logged (1153) then discarded, so an S=0 dynamic name reference is resolved against the static table (RFC 9204 4.3.2 violation → dynamic-table desync). StaticTable::lookup(uint16_t index) at lines 1220-1227 indexes STATIC_HEADER_FIELDS[index] with no bounds check; the array has 99 entries (0-98, confirmed). index is a peer-controlled QPACK varint truncated to uint16_t (0..65535) in _read_insert_with_name_ref (the guard only rejects on decode failure), so index >= 99 yields an out-of-bounds read. No mutex/lifetime/reference-count concern applies — this is synchronous decode-time logic on peer input. I searched for any caller-side or lookup-side bounds guard and found none (the peer branches at 709 and 756 use the same unchecked lookup).

#### [high] QPACK integer/string decode errors are swallowed by '&&' instead of '||', causing uninitialized reads and pointer underflow
**`src/proxy/http3/QPACK.cc:923`** · _memory-bug_ · **confirmed** · _fix available: master #19/#20 (&& -> ||)_

Throughout QPACK the return value of xpack_decode_integer/xpack_decode_string is checked with the pattern `(ret = decode(...)) < 0 && tmp > 0xFFFF`. The intent is clearly 'error if decode failed OR value too large', but '&&' means the error is only taken when BOTH hold, so genuine decode failures (ret == XPACK_ERROR_COMPRESSION_ERROR == -1) with a small/typical value are silently ignored. xpack_decode_integer returns -1 without writing its out-param when buf_start>=buf_end (XPACK.cc:66), so the code then uses an uninitialized value and adds the negative ret to a pointer/length. Concrete memory-safety case in _decode_header: `uint64_t tmp;` is uninitialized (line 922); for a header block whose prefix is truncated/empty (e.g. an HTTP/3 HEADERS block of length 0, reachable via Http3HeaderVIOAdaptor.cc:63 -> decode() -> _decode()), xpack_decode_integer returns -1, tmp stays garbage, the `&& tmp > 0xFFFF` guard often passes, then `pos += ret` moves pos before the buffer and `remain_len -= ret` underflows the size_t, so the subsequent decodes read out of bounds. The same swallow-then-consume pattern appears in decode() (286), _read_insert_with_name_ref (1515,1522), _read_insert_without_name_ref (1546,1553), _read_duplicate (1576), _read_dynamic_table_size_update (1598), and _read_table_state_synchronize (1620), where a negative ret is added to read_len and passed to reader.consume().

```
uint64_t tmp;   // line 922, uninitialized
if ((ret = xpack_decode_integer(tmp, pos, pos + remain_len, 8)) < 0 && tmp > 0xFFFF) {
  return -1;
}
pos        += ret;        // ret may be -1 -> pos underflows before buffer
remain_len -= ret;        // size_t underflow
```

**Fix:** Change every `ret < 0 && tmp > 0xFFFF` to `ret < 0 || tmp > 0xFFFF` (and treat ret<0 as a hard error before touching tmp), and initialize local decode temporaries. Do not advance pos/read_len when ret is negative.

**Verification:** The `&&` logic bug and uninitialized `tmp` are both literally present at QPACK.cc:922-923, and the pattern repeats at lines 286, 1515, 1546/1553, 1576, 1598, 1620. xpack_decode_integer (XPACK.cc:66) returns -1 WITHOUT writing its out-param when buf_start>=buf_end, so on a swallowed error the code uses garbage. Traced end-to-end: Http3HeadersFrame::_parse (Http3Frame.cc:348) sets _header_block_len = _length straight from the wire varint with no minimum-length check, so a length-0 HEADERS frame gives header_block_len==0; Http3HeaderVIOAdaptor::handle_frame (line 63) -> QPACK::decode (tmp initialized to 0 there, so it passes through) -> _decode -> _decode_header(hb, 0). In _decode_header tmp (line 922) is uninitialized; the first xpack_decode_integer returns -1 leaving tmp garbage; when garbage <= 0xFFFF the `&& tmp > 0xFFFF` guard does NOT fire, so `pos += ret` sets pos = header_block-1 and `remain_len -= ret` underflows to 1. The next decode reads *(header_block-1) (before-buffer OOB read) and largest_reference/base_index are uninitialized. I searched for an upstream guard rejecting empty/zero-length header blocks and found none; the frame layer only checks that the whole payload has arrived, not that length>0. No mutex/lifetime concern applies since this is synchronous parse logic. Soft spots: relies on malloc(0) returning non-null (standard glibc) and uninitialized tmp<=0xFFFF, but the uninitialized-value use itself is a certain defect independent of those.

#### [medium] QPACK base_index computation underflows uint16_t on crafted Header Data Prefix
**`src/proxy/http3/QPACK.cc:940`** · _logic-bug_

In _decode_header, base_index is computed as `largest_reference - delta_base_index` (sign bit set) with both operands uint16_t. A peer can send delta_base_index > largest_reference, wrapping base_index to a large value. base_index is then fed to _calc_absolute_index_from_relative_index / _calc_absolute_index_from_postbase_index (which themselves do unchecked uint16 subtraction/addition, lines 1258-1279) to form absolute dynamic-table indices. Combined with the '&&' error-swallow on the delta decode (line 932, which also uses an inconsistent `delta_base_index < 0xFFFF` guard rather than `> 0xFFFF`), a crafted prefix yields arbitrary absolute indices. XpackDynamicTable::lookup does validate ranges so this is contained to decode failures/desync rather than OOB in the common path, but the arithmetic is unvalidated and inconsistent with the rest of the file.

```
if (pos[0] & 0x80) {
  if (delta_base_index == 0) { return -3; }
  base_index = largest_reference - delta_base_index;   // uint16 underflow if delta > largest
} else {
  base_index = largest_reference + delta_base_index;   // uint16 overflow
}
```

**Fix:** Validate delta_base_index <= largest_reference before subtracting (and bound the sum), returning a decompression error otherwise; fix the `< 0xFFFF` guard on line 932 to match the intended `> 0xFFFF` overflow check.

#### [low] QPACK decoder-stream handler processes only one instruction per read and mis-accounts VIO ndone
**`src/proxy/http3/QPACK.cc:1105`** · _logic-bug_

_on_decoder_stream_read_ready uses `if (reader.is_read_avail_more_than(0))` and handles a single instruction, whereas the encoder-stream counterpart _on_encoder_stream_read_ready correctly loops with `while`. If a peer coalesces multiple decoder instructions (Header Acknowledgement / Stream Cancellation / Table State Synchronize) into one read-ready delivery, only the first is processed and the remainder sit unconsumed until the next read event (or are never processed if no more data arrives), stalling reference-count release and largest-known-received-index updates. Separately, in _on_read_ready the handlers return EVENT_DONE, and that return value is accumulated as `vio->ndone += nread` (line 1083) as though it were a byte count, which is meaningless bookkeeping.

```
int
QPACK::_on_decoder_stream_read_ready(IOBufferReader &reader)
{
  if (reader.is_read_avail_more_than(0)) {   // encoder path uses while()
    uint8_t buf;
    reader.memcpy(&buf, 1);
    ...
  }
  return EVENT_DONE;
}
```

**Fix:** Loop with `while (reader.is_read_avail_more_than(0))` as the encoder path does, and return/accumulate the actual number of bytes consumed rather than the event code.


### Security Hardening (wire-facing)  (1 critical, 1 high, 1 medium)

_The HTTP/3 QPACK decoder (src/proxy/http3/QPACK.cc) contains several confirmed memory-safety and error-handling defects reachable directly from untrusted client input on the request path. Most seriously, the QPACK static-table lookup performs no bounds check on an index taken from the wire, giving a straightforward out-of-bounds read; and a pervasive operator-precedence bug (`&&` where `||` was intended) causes decoder error returns to be ignored, after which negative return values are added into pointers and lengths, corrupting the parse bounds. By contrast the HTTP/2 HPACK decoder in the same tree bounds-checks its static table correctly, showing these are QPACK-specific oversights. Config parsers (IPAllow) and the HPACK integer/string decoders reviewed alongside were sound. HTTP/3 must be enabled (QUIC build) for these paths to be reachable._

#### [critical] QPACK static-table lookup has no bounds check: OOB read from wire-controlled index
**`src/proxy/http3/QPACK.cc:1222`** · _memory-bug_ · **confirmed** · _fix available: master #63 (static-table bounds + is_static)_

QPACK::StaticTable::lookup(uint16_t index, ...) indexes the fixed 99-entry STATIC_HEADER_FIELDS array directly with an index taken from the client-supplied header block, with no range check, and unconditionally returns MatchType::EXACT. The QPACK static table has entries 0..98, but the index is decoded by xpack_decode_integer and can be up to 0xFFFF. Every caller that resolves a static reference passes this wire value straight in: _decode_indexed_header_field (line 709, `if (buf[0] & 0x40) result = StaticTable::lookup(index, ...)`), _decode_literal_header_field_with_name_ref (line 756), and the encoder-stream insert handler (line 1156). Because lookup always reports EXACT, the caller then dereferences the returned name/value pointers and lengths (STATIC_HEADER_FIELDS[index].name / .name_len) read from past the end of the array, and _attach_header copies name_len bytes from an attacker-influenced pointer/length — an out-of-bounds read that can crash the server or leak adjacent memory into the reconstructed header set. The HPACK decoder in the same repo does this correctly: HpackIndexingTable::get_header_field (src/proxy/http2/HPACK.cc:340) checks `index < TS_HPACK_STATIC_TABLE_ENTRY_NUM` and returns HPACK_ERROR_COMPRESSION_ERROR otherwise. A malicious HTTP/3 client sending an indexed (static) header field, a literal-with-static-name-ref, or an encoder-stream Insert-With-Name-Reference with index >= 99 triggers it.

```
const XpackLookupResult
QPACK::StaticTable::lookup(uint16_t index, const char **name, size_t *name_len, const char **value, size_t *value_len)
{
  const Header &header = STATIC_HEADER_FIELDS[index];   // no check that index < countof(STATIC_HEADER_FIELDS) == 99
  *name      = header.name;
  *name_len  = header.name_len;
  *value     = header.value;
  *value_len = header.value_len;
  return {index, XpackLookupResult::MatchType::EXACT};   // always EXACT -> caller never rejects
}
```

**Fix:** Bounds-check index against countof(STATIC_HEADER_FIELDS) at the top of StaticTable::lookup(uint16_t,...) and return {0, MatchType::NONE} when out of range; have every caller treat a non-EXACT result as a QPACK decoding error (as the dynamic-table path already does at lines 714 and 761).

**Verification:** Traced end-to-end at /home/user/ats-10.2/src/proxy/http3/QPACK.cc. StaticTable::lookup (lines 1219-1227) indexes STATIC_HEADER_FIELDS[index] with zero bounds check; array has exactly 99 entries (definition lines 40-140, closing `};` at 140; 99 initializers counted), valid 0-98. The function unconditionally returns MatchType::EXACT. index originates from xpack_decode_integer on the client-supplied header block as uint64_t, passed straight in (truncated to uint16_t, still 0-65535). Callers _decode_indexed_header_field (line 709) and _decode_literal_header_field_with_name_ref (line 756) guard only `if (result.match_type != EXACT) return -1;` which is dead for static refs since lookup always returns EXACT; they then call _attach_header copying name_len bytes from the OOB-read pointer. Reachable via public QPACK::decode (273) -> _decode (303) -> _decode_header (915) -> dispatch (954/956); the header-data-prefix decode does not sanitize the index. Encoder-stream path _on_encoder_stream_read_ready (1156) calls StaticTable::lookup(index) unconditionally; _read_insert_with_name_ref (1514) only rejects index > 0xFFFF, never >= 99. No mutex/continuation/lifetime guard is relevant — this is a missing-bounds-check OOB read on a wire-controlled index, not a race. HPACK.cc:340 does the check correctly, confirming the intended guard is absent here. Every claimed line, caller, and array size matches.

#### [high] QPACK decoder ignores decode errors (&& instead of ||), then adds negative return into pointers/lengths
**`src/proxy/http3/QPACK.cc:923`** · _memory-bug_ · **confirmed** · _fix available: master #19/#20 (&& -> ||)_

Throughout the QPACK decoder the error checks combine the decode result and a range test with `&&` where `||` was intended. Because xpack_decode_integer/xpack_decode_string set their out-parameter to a small value before failing (dst = *p & mask), on a genuine COMPRESSION_ERROR (ret < 0) the second operand is false and the guard does not fire. Execution then continues and the negative `ret` is added into a pointer or an unsigned length. In the main request-header path _decode_header (line 923: `(ret = xpack_decode_integer(tmp, pos, pos+remain_len, 8)) < 0 && tmp > 0xFFFF`) a malformed Header Data Prefix that runs its continuation bytes to the end of the block makes xpack_decode_integer return -1; the guard is skipped, then `pos += ret` moves pos before the buffer and `remain_len -= ret` inflates the remaining length, so pos[0] is read out of bounds (line 936) and the sub-decoders parse with a corrupted base pointer/bound. The encoder-stream handlers are worse: read_len is size_t, so `read_len += ret` with ret==-1 underflows to SIZE_MAX and the next `input + read_len` is a wild pointer (e.g. _read_insert_with_name_ref lines 1515/1522/1526-1527, _read_insert_without_name_ref 1546/1553, _read_duplicate 1576, and 1598/1620). Line 932 shows the confusion directly, testing `delta_base_index < 0xFFFF`, the opposite polarity, so an over-large valid value is never rejected. All of these are driven by untrusted HTTP/3 client bytes.

```
// _decode_header (request path)
if ((ret = xpack_decode_integer(tmp, pos, pos + remain_len, 8)) < 0 && tmp > 0xFFFF) { return -1; }
pos        += ret;          // ret can be -1 -> pos moves before buffer
remain_len -= ret;          // -= (-1) inflates the bound
...
if ((ret = xpack_decode_integer(delta_base_index, pos, pos + remain_len, 7)) < 0 && delta_base_index < 0xFFFF) { return -2; }
// _read_insert_with_name_ref (encoder stream), read_len is size_t
if ((ret = xpack_decode_integer(tmp, input, input + input_len, 6)) < 0 && tmp > 0xFFFF) { return -1; }
index     = tmp;
read_len += ret;            // ret==-1 -> read_len underflows to SIZE_MAX
```

**Fix:** Change every `... ) < 0 && <range>` guard to reject on error OR out-of-range: `if (ret < 0 || tmp > 0xFFFF) return -1;` (and fix line 932's polarity). Never advance pos/read_len before confirming ret >= 0. Consider making read_len signed or checking ret >= 0 before the `+=`.

**Verification:** The `&&`/`||` defect is real and present in the source, and it produces out-of-bounds reads reachable from untrusted HTTP/3 bytes.

1. xpack_decode_integer (src/proxy/hdrs/XPACK.cc:64-97) writes the out-param BEFORE it can fail: line 71 `dst = (*p & ((1<<n)-1))`, and the continuation path is only entered when `dst == (1<<n)-1` (a small value like 255 for n=8, 63 for n=6). It then returns XPACK_ERROR_COMPRESSION_ERROR (= -1, per include/proxy/hdrs/XPACK.h:30) when the varint runs off the end (++p >= buf_end, line 76). So on a genuine error, dst is small and negative ret is returned.

2. Request path _decode_header (src/proxy/http3/QPACK.cc:923): `(ret = xpack_decode_integer(tmp,pos,pos+remain_len,8)) < 0 && tmp > 0xFFFF`. With a truncated leading 0xFF, ret=-1 and tmp=255, so `-1<0 && 255>0xFFFF` = false — guard skipped. Then line 926 `pos += ret` -> header_block-1 and line 927 `remain_len -= ret` -> len+1. The next decode (line 932) and line 936 `pos[0]` then read *(header_block-1), a 1-byte OOB read before the buffer. Reachability: decode() (QPACK.cc:273) carries the same broken guard at line 287 and would normally block on largest_reference=255, but once the dynamic table is grown via encoder-stream inserts, _resume_decode() calls _decode()->_decode_header() (QPACK.cc:1039/987) directly with the truncated block, so the OOB is reachable.

3. Encoder-stream handlers are worse because read_len is size_t and ret is int. In _read_insert_with_name_ref (QPACK.cc:1501-1530): a single instruction byte 0xBF (Insert-With-Name-Ref, 6-bit prefix all-ones) makes xpack_decode_integer return -1 with tmp=63; guard `-1<0 && 63>0xFFFF` = false; then line 1516 `read_len += ret` underflows read_len 0 -> SIZE_MAX, and line 1519 passes `input + read_len` (= input-1 after wrap) as buf_start to xpack_decode_string, which dereferences *(input-1) — a 1-byte OOB stack read. The dispatcher (_on_encoder_stream_read_ready, QPACK.cc:1135) only checks the return value AFTER the call, so _abort_decode() cannot prevent the OOB that already happened. Same pattern in _read_insert_without_name_ref, _read_duplicate, _read_dynamic_table_size_update, _read_table_state_synchronize. These bytes come straight off the client's QPACK encoder stream with no full-instruction framing guarantee, so truncated varints are attacker-triggerable.

I could not find any guard that fires on the error before the pointer/length arithmetic executes.

#### [medium] Encoder-stream Insert-With-Name-Reference ignores the S (static/dynamic) flag
**`src/proxy/http3/QPACK.cc:1156`** · _logic-bug_ · _fix available: master #63 (honor is_static)_

_read_insert_with_name_ref decodes the S flag into is_static (line 1511, `is_static = input[0] & 0x40`) and returns it, but _on_encoder_stream_read_ready ignores it and always resolves the name via StaticTable::lookup(index, ...) at line 1156. Per RFC 9204, when S is clear the index refers to the dynamic table; here a dynamic-table name reference is resolved against the static table instead, inserting the wrong entry — and, combined with the missing bounds check in finding 1, a dynamic index >= 99 becomes an out-of-bounds static-table read during dynamic-table insertion. The static/dynamic branch is handled correctly elsewhere (e.g. _decode_literal_header_field_with_name_ref lines 755-760), so this call site is inconsistent.

```
if (this->_read_insert_with_name_ref(reader, is_static, index, this->_arena, &value, value_len) < 0) { ... }
...
StaticTable::lookup(index, &name, &name_len, &dummy, &dummy_len);   // is_static never consulted
this->_dynamic_table.insert_entry(name, name_len, value, value_len);
```

**Fix:** Branch on is_static: when false, resolve the name through _dynamic_table.lookup(absolute index) as the request-decode path does; only use StaticTable::lookup when is_static is set, and treat a non-EXACT/out-of-range result as a decoder error that aborts the connection.


### Cache  (1 high, 1 medium, 1 low)

_I audited src/iocore/cache in ATS 10.2.1 (Cache/CacheRead/CacheWrite/CacheDir/Stripe/StripeSM, the aggregation write buffer, evacuation, and the three RAM caches) reading the real code and its callers/locking. The write/aggregation/evacuation and directory core are consistent under the stripe mutex, and the previously-known openReadStartEarliest recursion UAF is genuinely fixed (thread-local counter). The strongest issue is a RAM-cache correctness bug: the LRU and S3-FIFO policies silently ignore the copy-in-copy-out contract, which corrupts cached HTTP headers when ram_cache.compress is enabled (LRU is the configured default algorithm). I also found an ineffective directory-cleanup path after aggregation write errors and a RAM metric-accounting gap. No confirmed use-after-free on the cancel/abort paths was found beyond the already-fixed one._

#### [high] RAM cache LRU/S3-FIFO ignore the copy flag, corrupting cached HTTP headers when ram_cache.compress is enabled
**`src/iocore/cache/RamCacheLRU.cc:186`** · _memory-bug_ · **refuted**

RamCache::put has a copy-in-copy-out contract: when copy=true the policy must store a private copy of the buffer, because the caller mutates the original afterwards. CacheVC::handleReadDone (CacheVC.cc:418-456) relies on this: when proxy.config.cache.ram_cache.compress is non-zero it sets http_copy_hdr=true, calls stripe->ram_cache->put(read_key, buf.get(), doc->len, /*copy=*/http_copy_hdr, o) with the still-MARSHALLED header buffer (line 442), and then unmarshals that same buf IN PLACE (lines 454-456). RamCacheCLFUS honors copy (it mallocs and memcpys before storing). RamCacheLRU::put and RamCacheS3FIFO::put both drop the argument (the parameter is an unnamed 'bool', with the comment "ignore 'copy' since we don't touch the data") and store e->data = data, i.e. the SAME refcounted IOBufferData. The subsequent in-place unmarshal therefore rewrites the bytes of the object now living in the RAM cache. On a later RAM hit, handleRead (CacheVC.cc:480) routes compressed HTTP docs back through handleReadDone, whose from_ram path (http_copy_hdr=false) unmarshals the already-unmarshalled buffer again (line 423) -> HTTPInfo::unmarshal returns <0 -> ink_assert(!"unmarshal failed") in debug, or okay=0 plus a bad/garbage vector (ECACHE_BAD_META_DATA, dir removal) in release. Because the buffer is a shared Ptr handed to multiple concurrent readers (also cached in stripe->first_fragment_data at line 450), the in-place mutation is also a data race on live buffer contents. This is the DEFAULT-algorithm path: proxy.config.cache.ram_cache.algorithm defaults to 1 = LRU (RecordsConfig.cc:874, Cache.h:40), and there is no guard tying compress to CLFUS (CacheProcessor.cc:1461 selects the policy, 1614 validates only the compression TYPE). Fix: honor the copy flag in both LRU and S3-FIFO put() exactly as CLFUS does, or reject/force-off ram_cache.compress for non-CLFUS algorithms.

```
RamCacheLRU.cc:184-186 `// ignore 'copy' since we don't touch the data`\n`int RamCacheLRU::put(CryptoHash *key, IOBufferData *data, [[maybe_unused]] uint32_t len, bool, uint64_t auxkey)` ... `e->data = data;`  (RamCacheS3FIFO.cc:342 is identical: `put(..., bool, uint64_t auxkey)` then `ne->data = data;`). CacheVC.cc:442 `stripe->ram_cache->put(read_key, buf.get(), doc->len, http_copy_hdr, o);` followed by CacheVC.cc:454-456 `if (http_copy_hdr && ... okay) { unmarshal_helper(doc, buf, okay); }`. Contrast RamCacheCLFUS.cc:757-760 which copies: `char *b = ats_malloc(len); memcpy(b, data->data(), len); e->data = new_xmalloc_IOBufferData(b, len);`
```

**Fix:** Implement copy semantics in RamCacheLRU::put and RamCacheS3FIFO::put (malloc+memcpy into a fresh IOBufferData when copy==true), matching CLFUS; alternatively force cache_config_ram_cache_compress off unless algorithm==CLFUS and log a warning.

**Refuted:** The claim's mechanism (LRU/S3-FIFO put drop the copy flag and store the same IOBufferData at RamCacheLRU.cc:227 / RamCacheS3FIFO.cc:342; CacheVC.cc:442 puts marshalled buf then unmarshals in place at 454-456; no guard tying compress to CLFUS at CacheProcessor.cc:1614-1627; default algorithm LRU) is read correctly. But the alleged failure — that a later RAM hit re-unmarshals the already-unmarshalled buffer and HTTPInfo::unmarshal returns <0, hitting ink_assert(!\"unmarshal failed\")/ECACHE_BAD_META_DATA — is prevented by an explicit idempotency guard the reviewer missed. HTTPInfo::unmarshal (HTTP.cc:2202-2207) and unmarshal_v24_1 (HTTP.cc:2269-2274) test alt->m_magic: the first unmarshal sets it to CacheAltMagic::ALIVE (HTTP.cc:2214) and records m_unmarshal_len (2258); on re-entry with m_magic==ALIVE the function returns the positive m_unmarshal_len with the comment \"Already unmarshaled, must be a ram cache\" — never <0. CacheAltMagic ALIVE(0xabcddeed) vs MARSHALED(0xdcbadeed) are distinct (HTTP.h:1367-1371). In unmarshal_helper (CacheVC.cc:334-345) that positive return advances the loop by exactly the bytes consumed originally, so it terminates cleanly with okay=1 — the double-unmarshal is a designed no-op, not corruption. This branch exists specifically for a RAM cache that holds unmarshalled HTTPInfo, which is exactly what LRU/S3-FIFO store. CLFUS copies to hold a compressed representation (memory saving), not for unmarshal correctness; ignoring copy in LRU/S3-FIFO forfeits compression but does not corrupt headers. The data-race sub-claim is likewise refuted: RAM get/put, the in-place unmarshal, and first_fragment_data all occur under stripe->mutex (handleReadDone MUTEX_TRY_LOCK at CacheVC.cc:367; handleRead asserts stripe mutex held at 471), so accesses are serialized.

#### [medium] aggWriteDone write-error cleanup builds del_dir with a byte offset instead of a block (vol) offset, so the directory entries it intends to delete are never matched
**`src/iocore/cache/StripeSM.cc:761`** · _logic-bug_

On an aggregation disk-write failure, aggWriteDone tries to remove every directory entry it inserted for the fragments in the failed buffer. It sets the search key's offset with dir_set_offset(&del_dir, directory.header->write_pos + done) -- a raw BYTE position (write_pos and done are byte quantities). But the directory entries for those fragments were inserted with a BLOCK offset: _copy_writer_to_aggregation sets dir_set_offset(&vc->dir, this->offset_to_vol_offset(doc_offset)) (StripeSM.cc:967) and openWriteWriteDone inserts that dir. Directory::remove matches on `offset == dir_offset(del)` (CacheDir.cc:702), comparing the stored block offset against del_dir's byte offset, so it never matches and removes nothing; the loop's intent (roll back the inserted entries) silently fails. Impact is partially masked because the failed write did not advance write_pos and reset the agg buffer, so Stripe::dir_valid()/dir_agg_valid() classify those entries as invalid and probe() lazily deletes them or treats a later real write at the same offset as a tag collision -- but this masking is fragile and the cleanup is dead. (Note: this line is identical in current master, i.e. a longstanding upstream defect, not a 10.2 regression.) Fix: dir_set_offset(&del_dir, this->offset_to_vol_offset(directory.header->write_pos + done)).

```
StripeSM.cc:757-764 `Dir del_dir; dir_clear(&del_dir); for (int done = 0; done < this->_write_buffer.get_buffer_pos();) { Doc *doc = ...; dir_set_offset(&del_dir, directory.header->write_pos + done); this->directory.remove(&doc->key, this, &del_dir); done += round_to_approx_size(doc->len); }` vs insertion at StripeSM.cc:967 `dir_set_offset(&vc->dir, this->offset_to_vol_offset(doc_offset));` and match at CacheDir.cc:702 `if (dir_compare_tag(e, key) && offset == dir_offset(del))`.
```

**Fix:** Convert the byte position to a vol/block offset before storing it in del_dir: `dir_set_offset(&del_dir, this->offset_to_vol_offset(directory.header->write_pos + done));`

#### [low] S3-FIFO ghost-queue metadata is counted in the budget but omitted from the ram_cache.bytes_used gauge
**`src/iocore/cache/RamCacheS3FIFO.cc:171`** · _quality_

S3-FIFO charges each ghost key ENTRY_OVERHEAD against the configured budget (put()'s admission test at line 382 and size() at line 171 both include _g_count * ENTRY_OVERHEAD), but the exported ram_cache_bytes gauge only ever receives resident bytes: put() increments the gauge by `need` on resident insert (line 409), _to_ghost() decrements the full resident amount when demoting to ghost (lines 241-242), and _remove() of a SEG_GHOST entry adjusts no gauge (lines 201-203). As a result proxy.process.cache...ram_cache.bytes_used under-reports actual memory by up to ghost_mem_percent of the cache size whenever the ghost queue is populated, and the gauge diverges from size(). This is an observability/accounting inaccuracy only, not a memory-safety issue, but it makes the RAM-cache memory metric misleading for the new algorithm.

```
RamCacheS3FIFO.cc:171 `return _s_bytes + _m_bytes + _g_count * ENTRY_OVERHEAD;` while _remove() ghost branch (lines 201-203) does `_g_bytes -= e->size; _g_count--;` with no ts::Metrics::Gauge::decrement, and _to_ghost() (241-242) decrements the gauge by the resident `ENTRY_OVERHEAD + e->size` so the ghost's own overhead never appears in the gauge.
```

**Fix:** Account the ghost per-key ENTRY_OVERHEAD in the ram_cache_bytes gauge consistently with size()/the budget check (add on demote-to-ghost, subtract on ghost removal), or explicitly document that the gauge tracks only resident data.


### Concurrency & Locking  (2 low)

_I audited the race/locking-discipline lens across the named priority targets. The bulk of this code is well-hardened: PluginVC's active/passive sides share a single core mutex so cross-side accesses are protected, and every MUTEX_TRY_LOCK miss path (PluginVC, Http2Stream, HostDB continuations, HttpSessionManager pool acquire/release) reschedules rather than dropping work. HttpSessionManager global-vs-thread pool operations serialize consistently on the pool mutex (recursive ProxyMutex re-locks are fine), and the global-pool eventHandler and acquireSession both run under m_g_pool->mutex, so migrateToCurrentThread is not exposed to stray cross-thread events. ConnectionTracker's connection counters are atomic and the reserve/drop/release accounting (including the double-checked table-erase in Group::release) is symmetric and correct. I confirmed only two low-severity issues, both non-crashing: a lost-max-update in a non-looping weak CAS, and a bounded lost-wakeup window in the cond-var signaling path._

#### [low] update_max_count uses a single non-looping weak CAS and can silently drop a higher observed maximum
**`include/iocore/net/ConnectionTracker.h:490`** · _race_

TxnState::update_max_count() is called without any lock, concurrently by transactions on different event threads that share the same outbound Group. It loads _count_max, and if the new count is larger performs a single compare_exchange_weak(cmax, count) with no retry loop. If the CAS fails (another thread updated _count_max concurrently, or a spurious weak failure), the function returns without retrying even though the caller observed a count strictly greater than the value now stored. Concretely: _count_max=5; thread A observes count=10, thread B observes count=8; B's CAS(5->8) lands first; A's CAS(5->10) then fails because cmax is now 8, and A does not retry, so _count_max stays 8 despite a real observed peak of 10. The authoritative connection count (_count) is unaffected -- this only corrupts the reported peak-connections gauge -- so impact is limited to monitoring/metrics accuracy.

```
auto cmax = _g->_count_max.load();
  if (count > cmax) {
    _g->_count_max.compare_exchange_weak(cmax, count);
  }
```

**Fix:** Use a CAS loop: while (count > cmax && !_count_max.compare_exchange_weak(cmax, count)) {} so a failed exchange re-reads cmax and retries until either the store succeeds or a concurrent update already recorded an equal-or-greater max.

#### [low] ProtectedQueue signalActivity/try_signal can lose a wakeup in the waiter's check-then-cond_timedwait window
**`src/iocore/eventsystem/ProtectedQueue.cc:47`** · _race_

For threads that use the default cond-var tail handler (EThread::DefaultTailHandler), enqueue() pushes the event onto the lock-free atomiclist and then, only when the list was previously empty, calls e_ethread->tail_cb->signalActivity(), which is try_signal() -- it attempts ink_mutex_try_acquire(&lock) and does nothing if the lock is busy. The waiting thread runs wait() while holding EThread::lock: it evaluates INK_ATOMICLIST_EMPTY(al) && localQueue.empty() and, if empty, calls ink_cond_timedwait which only then atomically releases lock. There is a window where the waiter has already evaluated the queue as empty but has not yet released the lock inside cond_timedwait; an enqueue that lands in that window pushes to al and its try_signal fails to acquire the held lock, so no signal is delivered. The waiter then sleeps despite a pending event. It is not a permanent hang -- the wait() timeout bounds the delay -- and the try_signal 'skip if busy' behavior is a deliberate optimization, but the transition-into-wait case makes it a genuine lost-wakeup that delays event delivery on cond-var-waiting threads by up to the loop timeout.

```
bool was_empty       = (ink_atomiclist_push(&al, e) == nullptr);
  if (was_empty) {
    EThread *inserting_thread = this_ethread();
    if (inserting_thread != e_ethread) {
      e_ethread->tail_cb->signalActivity();
    }
  }
```

**Fix:** Either have signalActivity for the cond-var handler take the lock unconditionally (as ProtectedQueue::signal() does) rather than try_signal, or re-check the atomiclist after acquiring EThread::lock and immediately before entering cond_timedwait so an event enqueued in the window is observed instead of slept through.


### HTTP/1.x State Machine  (1 medium, 1 low)

_The HTTP/1.x proxy state machine and tunnel teardown code is mature and heavily guarded; most kill_this/terminate_sm, vc_table cleanup, and tunnel producer/consumer teardown paths are internally consistent (e.g. remove_entry vs cleanup_entry, background-fill detach, half-close handling in state_watch_for_client_abort). I did not confirm any exploitable use-after-free or double-free on the main request/response paths. The concrete issues I could verify are a set of unguarded server_txn->get_netvc() dereferences on origin error paths (ProxyTransaction::get_netvc() can legitimately return nullptr, and the same file guards it elsewhere), and a contradictory assert-then-guard in HttpCacheSM. Severity is bounded because the null-netvc window is narrow and mostly tied to intercept/PluginVC or torn-down connections rather than ordinary TCP origins._

#### [medium] Unguarded server_txn->get_netvc()->lerrno on origin error paths can null-deref
**`src/proxy/http/HttpSM.cc:6454`** · _memory-bug_

In handle_server_setup_error (VC_EVENT_ERROR case, line 6454), tunnel_handler_post_server (VC_EVENT_ERROR, line 4163), and handle_post_failure (line 6328), the code dereferences server_txn->get_netvc()->lerrno without a null check. ProxyTransaction::get_netvc() returns `(_proxy_ssn) ? _proxy_ssn->get_netvc() : nullptr` and ProxySession::get_netvc() returns _vc, which is cleared once the underlying NetVConnection is detached/closed (ProxySession even exposes is-null checks on it). The same source file guards get_netvc() against null in most other uses (e.g. handle_http_server_open line 6349 `if (vc)`, line 5482 `if (auto *netvc = ...; netvc)`), showing the invariant that it may be null. On an origin whose netvc has already been torn down, or an intercept/PluginVC-backed server transaction (the comment at lines 6403-6405 acknowledges the synthetic error-event hack for non-existent listening ports), the VC_EVENT_ERROR branch dereferences a null pointer and crashes the process on the request path.

```
case VC_EVENT_ERROR:
    t_state.current.state = HttpTransact::CONNECTION_ERROR;
    t_state.set_connect_fail(server_txn->get_netvc()->lerrno);
    break;   // (also HttpSM.cc:4163 and HttpSM.cc:6328, same pattern)
```

**Fix:** Fetch the netvc into a local, and fall back to a sentinel errno (e.g. ECONNABORTED/EPIPE) when it is null: `NetVConnection *nvc = server_txn->get_netvc(); t_state.set_connect_fail(nvc ? nvc->lerrno : ECONNABORTED);` at all three sites.

#### [low] HttpCacheSM state handlers assert the exact condition their guard then handles
**`src/proxy/http/HttpCacheSM.cc:130`** · _quality_

state_cache_open_read (line 130) and state_cache_open_write (line 216) both do `ink_assert(captive_action.cancelled == 0);` and then immediately `if (captive_action.cancelled == 1) { return VC_EVENT_CONT; }`. In a debug build the assert aborts before the guard can run, so if a cancelled captive action ever reaches these handlers the process aborts instead of taking the intended graceful early-return; in a release build the assert is compiled out and the guard is live. The two lines encode contradictory assumptions about whether a cancelled callback is reachable here. Either the guard is dead code that should be removed, or the assert is wrong and should be dropped so the graceful path works in debug too.

```
STATE_ENTER(&HttpCacheSM::state_cache_open_read, event);
  ink_assert(captive_action.cancelled == 0);
  pending_action = nullptr;

  if (captive_action.cancelled == 1) {
    return VC_EVENT_CONT; // SM gave up on us
  }
```

**Fix:** Decide the invariant: if a cancelled callback is genuinely impossible, delete the `if (captive_action.cancelled == 1)` guard; if it is possible, remove the contradicting `ink_assert(captive_action.cancelled == 0)` so debug builds do not abort on the handled case.


### Header / URL Parsing  (3 medium, 1 low)

_The scope files show a generally hardened parser: Content-Length/Transfer-Encoding combination handling, duplicate Content-Length dedup, integer overflow (std::from_chars), header field-name/value char validation, host/port validation, UINT16_MAX length caps, and HdrHeap coalesce stale-pointer protection (HeapGuard/m_locked) are all handled correctly. The real weaknesses are in robustness edges: an obs-fold continuation is silently dropped when a read boundary splits it (non-deterministic, TCP-segmentation-dependent parsing), the URL authority parser accepts non-digit trailing characters after a port and stores a textual port that disagrees with the numeric port, and the cache unmarshal path trusts an untrusted m_freetop / object length with no upper bound, permitting out-of-bounds access on a corrupted cache object. None are outright request-path memory corruption, but each is worth a maintainer's attention._

#### [medium] obs-fold continuation silently dropped when CRLF lands on an input-buffer boundary
**`src/proxy/hdrs/MIME.cc:2383`** · _logic-bug_

MIMEScanner::get() only detects an obs-fold (line-folding) continuation when the preceding LF and the next line's leading whitespace are in the same get() call. In the post-loop CONT cleanup, when state==AFTER and more input is not yet available (non-eof), it returns OK for the field immediately (m_state=BEFORE; zret=OK) instead of waiting to see whether the next byte is folding whitespace. The header parser is fed incrementally as bytes arrive, so if a read boundary falls right after a header's CRLF and before the continuation's leading SP/HT, the fold is not applied: the field is committed with its value truncated, and on the next get() the continuation line begins with whitespace, fails the is_token(*parsed) check in mime_parser_parse, and is discarded as a garbage line. The same request therefore parses to different header values depending only on TCP segmentation, which an on-path attacker can influence. The behavior is acknowledged in the in-code comment at lines 2329-2333 but remains unfixed.

```
// NOTE: obs-fold is only detected here when the LF and the continuation whitespace are in
// the same get() call. If the CRLF falls exactly at the end of an input buffer, the
// post-loop cleanup returns OK before we see the next byte, so the fold is silently lost
...
      } else if (MimeParseState::AFTER == m_state) {
        // After a field but we still have data. Need to parse it too.
        m_state = MimeParseState::BEFORE;
        zret    = ParseResult::OK;
      }
```

**Fix:** Return CONT while in AFTER state at a buffer boundary (non-eof) so the scanner waits for the next byte before deciding whether the previous field is complete, or reject obs-fold outright (RFC 7230 permits a 400). Either makes parsing independent of segmentation. As the comment notes, this affects all callers including TSMimeHdrParse, so coordinate the contract change.

#### [medium] URL authority parser accepts non-digit trailing characters in port; numeric and textual port disagree
**`src/proxy/hdrs/URL.cc:479`** · _logic-bug_

url_parse_internet() extracts the port substring as everything between the last colon and the authority terminator ('/', '?', '#', or EOS) without validating it is all digits (lines 1376-1383), and never runs it through the digit-strict validation used for the Host header. URLImpl::set_port() then iterates digits but breaks at the first non-digit while still storing the *entire* raw substring as m_ptr_port. For an input like "host:80abc/", m_port becomes the numeric 80 (used for the origin connection and for url_canonicalize_port in the cache key) while m_ptr_port/m_len_value retain "80abc" (emitted verbatim by url_print, e.g. when forwarding an absolute-form URI to a parent proxy or in logs). This violates RFC 3986 port = *DIGIT and creates two disagreeing port representations for the same URL, a normalization inconsistency that can drive cache-key vs. routing/forwarding divergence. Reachable via absolute-form request targets (forward-proxy) and CONNECT authority, where the port comes from the URL rather than the (digit-validated) Host header.

```
this->m_port = 0;
  for (auto digit : value) {
    if (!ParseRules::is_digit(digit)) {
      break;
    }
    unsigned int next = this->m_port * 10 + (digit - '0');
    ...
    this->m_port = static_cast<uint16_t>(next);
  }
  mime_str_u16_set(heap, value, &(this->m_ptr_port), &(this->m_len_port), copy_string);
```

**Fix:** Validate the port TextView is non-empty and all digits in url_parse_internet() (mirroring http_parse_host_header) and return ParseResult::ERROR otherwise; or in set_port() reject/refuse the value when a non-digit is encountered instead of storing raw text whose numeric interpretation was truncated.

#### [medium] Cache unmarshal trusts m_freetop and per-object length with no upper bound, allowing OOB access
**`src/proxy/hdrs/MIME.cc:3570`** · _memory-bug_

MIMEFieldBlockImpl::unmarshal() loops index from 0 to m_freetop over the fixed-size m_field_slots[MIME_FIELD_BLOCK_SLOTS] array (16 slots), but m_freetop is a uint32_t read straight from the marshalled buffer and is never checked against MIME_FIELD_BLOCK_SLOTS. A m_freetop > 16 (from a corrupted or truncated cache object) walks past the slot array, dereferencing adjacent memory as MIMEField and swizzling its m_ptr_name/m_ptr_value/m_next_dup, i.e. out-of-bounds reads and pointer writes. Relatedly, HdrHeap::unmarshal()'s outer loop (`while (obj_data < m_free_start) { ... obj_data += obj->m_length; }`) checks only that each object's *start* is in bounds, not that obj->m_length keeps the object within m_free_start, so the final object may extend past the mapped buffer. check_marshalled() validates the heap header but not these interior fields, and HDR_HEAP_CHECKSUMS is compile-time optional (off by default). This is the cache-read path (semi-trusted local storage), not a direct request path, so severity is bounded by the cache trust model.

```
for (uint32_t index = 0; index < m_freetop; index++) {
    MIMEField *field = &(m_field_slots[index]);
    if (field->is_live()) {
      HDR_UNMARSHAL_STR(field->m_ptr_name, offset);
      HDR_UNMARSHAL_STR(field->m_ptr_value, offset);
      if (field->m_next_dup) {
        HDR_UNMARSHAL_PTR(field->m_next_dup, MIMEField, offset);
      }
```

**Fix:** Clamp/validate m_freetop <= MIME_FIELD_BLOCK_SLOTS during unmarshal and bail out on violation; in HdrHeap::unmarshal add a check that obj_data + obj->m_length <= m_free_start before dispatching each object, returning -1 on overrun.

#### [low] Slow-path request-line version scan dereferences before bounds check (1-byte under-read)
**`src/proxy/hdrs/HTTP.cc:1009`** · _memory-bug_

In the slow-path request parser, parse_version1 walks backward from end-1 with conditions that evaluate the dereference before the lower-bound guard: `is_lf(*cur) && (cur >= line_start)`, `is_cr(*cur) && (cur >= line_start)`, and `while (is_ws(*cur) && (cur >= line_start)) cur -= 1;`. For a request line consisting entirely of whitespace, cur is decremented to line_start-1 and *cur is then read one byte before line_start before the `cur >= line_start` test short-circuits. The over-read is a single byte within the surrounding header buffer allocation so it is benign in practice, but the deref-before-bounds ordering is incorrect and fragile. Only reached in slow_case (line length < 16 or non-GET method).

```
while (ParseRules::is_ws(*cur) && (cur >= line_start)) {
      cur -= 1;
    }
    version_end = cur + 1;
```

**Fix:** Reorder each condition so the bound is checked first, e.g. `while ((cur >= line_start) && ParseRules::is_ws(*cur))`, in the three checks at lines 1001, 1004, and 1009.


### Plugin API  (1 high, 1 medium, 1 low)

_The plugin API surface in ATS 10.2.1 is broadly well guarded by sdk_assert checks, but two concrete robustness defects stand out on the remap-plugin path, both of which have fixes in the development tree that were never carried into this 10.2 release branch. The most serious is a genuine data race on a shared RemapPluginInfo member used to save/restore the thread-local plugin context across concurrent doRemap() dispatches. The second is an unconditional overwrite of a transaction's intercept tunnel that leaks a PluginVCCore and strands the first interceptor. A minor argument-validation gap in an SSL-context enumeration API can crash the server on negative input. Object lifetime for continuations across DSO unload is correctly protected by PluginThreadContext refcounting._

#### [high] Data race: remap plugin context save/restore uses a shared member instead of a stack local
**`src/proxy/http/remap/RemapPluginInfo.cc:278`** · _race_ · **confirmed** · _fix available: master #30 (stack-local context)_

setPluginContext()/resetPluginContext() save the previous thread-local plugin context into the shared RemapPluginInfo member _tempContext (declared once per plugin object in include/proxy/http/remap/RemapPluginInfo.h:113), not into a per-call stack local. The same RemapPluginInfo instance services every request matching a remap rule, and doRemap() runs concurrently on many net threads. Two (or more) threads entering doRemap()/osResponse() on the same plugin race on _tempContext: thread A executes `_tempContext = pluginThreadContext` while thread B does the same and both later read `pluginThreadContext = _tempContext`. This is an unsynchronized read/write of a non-atomic pointer (undefined behavior) on the hottest plugin path. Because pluginThreadContext drives PluginThreadContext::countInvocation() bookkeeping (INKContInternal.cc:162-164), a torn restore can leave a thread's thread-local context pointing at the wrong plugin or nulled, mis-attributing invocation counts and, in the nested-context case, restoring a stale value. The development branch fixes exactly this (commit 8b35d0120, 'remap: stop racing the shared plugin-context save/restore slot', Fixes #30) by returning the previous context from setPluginContext() and passing it back through a stack local; that fix is absent from 10.2.1.

```
setPluginContext():
  _tempContext        = pluginThreadContext;
  pluginThreadContext = this;
resetPluginContext():
  pluginThreadContext = _tempContext;
Header: PluginThreadContext *_tempContext = nullptr;  // shared per-plugin, written by every concurrent doRemap()
```

**Fix:** Return the previous context from setPluginContext() into a stack local at each call site and pass it to resetPluginContext(previous); remove the shared _tempContext member. Backport commit 8b35d0120.

**Verification:** Confirmed the race. Facts established from the 10.2 tree:

1. `pluginThreadContext` is `thread_local` (include/proxy/http/remap/RemapPluginInfo.h:37, defined src/proxy/ReverseProxy.cc:82). So set/reset legitimately need a save-slot for the previous value.

2. `_tempContext` is a plain non-static member of RemapPluginInfo (RemapPluginInfo.h:113, `PluginThreadContext *_tempContext = nullptr;`), i.e. one slot per plugin object, NOT a stack local. setPluginContext() (RemapPluginInfo.cc:276-281) writes `_tempContext = pluginThreadContext; pluginThreadContext = this;` and resetPluginContext() (RemapPluginInfo.cc:284-288) reads `pluginThreadContext = _tempContext;`.

3. The RemapPluginInfo instance is shared, not per-thread: RemapPluginInst holds `RemapPluginInfo &_plugin` (PluginFactory.h:63) and doRemap forwards to `_plugin.doRemap(...)` (PluginFactory.cc:76-79). One RemapPluginInfo per DSO services every remap rule/instance that references it.

4. No lock guards the call. RemapPlugins::run_single_remap (RemapPlugins.cc:64-65) calls `plugin->doRemap(...)` directly inside the HttpSM state-machine handler on the net thread. The only mutex held at dispatch (EThread::process_event) is the per-transaction HttpSM mutex — distinct for each transaction — so two transactions matching the same remap rule on different net threads execute setPluginContext()/doRemap()/resetPluginContext() on the SAME RemapPluginInfo concurrently with no synchronization.

Result: concurrent unsynchronized read+write of the non-atomic pointer `_tempContext` by multiple threads = data race / UB, exactly as claimed. I looked specifically for the process_event mutex guard the prompt flagged; it does not apply here because the acquired mutex is the SM's, not the plugin's, and the two racing SMs hold different mutexes. No per-thread copy, no atomic, no plugin-level lock exists. osResponse() (RemapPluginInfo.cc:238-246, called from HttpTransact.cc:4008) shares the same slot and adds a second concurrent writer.

I could not refute; the failure is real and fully traced. One severity caveat below.

#### [medium] TSHttpTxnIntercept/TSHttpTxnServerIntercept overwrite an existing intercept, leaking PluginVCCore
**`src/api/InkAPI.cc:6117`** · _logic-bug_ · _fix available: master #34 (reject dup intercept)_

Both TSHttpTxnServerIntercept (line 6106) and TSHttpTxnIntercept (line 6120) assign http_sm->plugin_tunnel = PluginVCCore::alloc(...) unconditionally after only checking txnp and contp with sdk_assert. If a plugin (or two cooperating plugins) installs an intercept on a transaction that already has one, the previously stored PluginVCCore pointer is overwritten with no cleanup: the earlier PluginVCCore is leaked and its interceptor continuation is stranded (it never gets its side of the tunnel wired up, so its TSVConn/resources hang for the life of the process). This is reachable purely through documented API misuse and is not rejected or diagnosed. The development branch adds an explicit guard that logs an error and ignores the duplicate (commit f4e5bb289, 'api: reject duplicate transaction intercept instead of leaking', Fixes #34); that guard is absent from 10.2.1.

```
http_sm->plugin_tunnel_type = HttpPluginTunnel_t::AS_SERVER;
  http_sm->plugin_tunnel      = PluginVCCore::alloc(reinterpret_cast<INKContInternal *>(contp), buffer_index, buffer_water_mark);
// no check that http_sm->plugin_tunnel was already non-null
```

**Fix:** Before assigning, if http_sm->plugin_tunnel != nullptr, Error() and return without overwriting. Backport commit f4e5bb289.

#### [low] TSSslClientContextsNamesGet: no validation of n before alloca(sizeof(...) * n)
**`src/api/InkAPI.cc:8148`** · _standards-gap_

TSSslClientContextsNamesGet sizes a stack buffer with `alloca(sizeof(std::string_view) * n)` where n is a plugin-supplied int. The only argument check is `sdk_assert(n == 0 || result != nullptr)`; n itself is never validated to be non-negative or bounded. A negative n is converted to size_t for the multiplication, yielding an enormous alloca that overflows the stack and crashes the server; a very large positive n does the same. This matches the class of missing argument-validation that lets plugin misuse take down the process, and unlike most other InkAPI entry points this one has no sdk_assert on the size parameter.

```
sdk_assert(n == 0 || result != nullptr);
  ...
  auto  mem          = static_cast<std::string_view *>(alloca(sizeof(std::string_view) * n));
```

**Fix:** Add sdk_assert(n >= 0) (and ideally an upper bound), or replace the alloca with a heap std::vector<std::string_view> sized to n to avoid unbounded stack growth.


### Standards Conformance & Missing Features  (1 high, 2 medium, 5 low)

_Audited ATS 10.2.1 (project VERSION 10.2.1, commit 31f1f2f3b) at /home/user/ats-10.2 against 12 HTTP-conformance items. SUPPORTED with code evidence: 103 Early Hints (HTTP.cc:736 status + HttpTransact.cc:4320-4323 forwards it like 100-continue); RFC 9213 CDN-Cache-Control (HdrToken.cc:131 token + MIME.cc:3695-3735 targeted_headers cooking wired via proxy.config.http.cache.targeted_cache_control_headers, HttpConfig.cc:1156); zstd Content-Encoding (plugins/compress/compress.cc:168-215, TS_HTTP_VALUE_ZSTD); TLS 0-RTT early data (src/iocore/net/TLSEarlyDataSupport.cc:75-91); RFC 9111 Age calculation is correct (HttpTransactCache.cc:615-668 implements apparent_age/corrected_received_age/response_delay/corrected_initial_age/resident_time). ABSENT/PARTIAL findings filed below (8, ranked by user impact): RFC 5861 SWR/SIE missing from core cache (plugin-only); RFC 8441 Extended CONNECT/WebSockets-over-H2/H3; RFC 9218 Extensible Priorities; HTTP QUERY method; RFC 9211 Cache-Status; RFC 8941 Structured Fields parser; RFC 9111 must-understand; TLS ECH. One additional low item not filed to stay within 8: RFC 8336 ORIGIN frame is also absent (no HTTP2_FRAME_TYPE_ORIGIN in HTTP2.h:169-180). Note: qualified no-cache=/private= arguments are parsed as blanket no-cache/private (MIME.cc:3746+ ignores the field-name arg), which is conservative and not a harmful conformance bug._

#### [high] RFC 5861 stale-while-revalidate / stale-if-error not honored by core cache
**`include/proxy/hdrs/MIME.h:214`** · _missing-feature_

The core Cache-Control cooking machinery has no cooked-mask bit for stale-while-revalidate or stale-if-error, so HttpTransact/HttpTransactCache freshness logic never parses or acts on these directives. They are supported only by the out-of-tree experimental stale_response plugin (plugins/experimental/stale_response/). Origins that emit these very widely-deployed directives get no async revalidation or stale-on-error behavior from the core cache; content simply revalidates synchronously or is treated as stale.

```
MIME.h:214-227 enumerates MIME_COOKED_MASK_CC_MAX_AGE...MIME_COOKED_MASK_CC_EXTENSION with no SWR/SIE entries; grep for 'stale.while|stale.if.error' in src/proxy/http/HttpTransact.cc and src/iocore/cache/ returns nothing; RFC 5861 handling exists only under plugins/experimental/stale_response/.
```

**Fix:** Add cooked-mask bits and MIME_VALUE_ tokens for stale-while-revalidate/stale-if-error, parse the integer args in recompute_cooked_stuff, and consult them in HttpTransact freshness/error paths.

#### [medium] RFC 8441 Extended CONNECT (WebSockets over HTTP/2 and HTTP/3) absent
**`include/proxy/http2/HTTP2.h:253`** · _missing-feature_

There is no SETTINGS_ENABLE_CONNECT_PROTOCOL (id 8) in the HTTP/2 settings identifier enum, and no handling of the :protocol pseudo-header for Extended CONNECT in HTTP/2 or HTTP/3. Clients cannot bootstrap WebSockets (or other protocols) over an HTTP/2 or HTTP/3 hop through ATS; such CONNECT upgrades are rejected/mishandled.

```
HTTP2.h:253-260 Http2SettingsIdentifier enum ends at HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE=6 with no id 8; grep for 'ENABLE_CONNECT_PROTOCOL|:protocol|extended.connect' across src/proxy/http2 and src/proxy/http3 finds no implementation.
```

**Fix:** Advertise SETTINGS_ENABLE_CONNECT_PROTOCOL and accept the :protocol pseudo-header, wiring Extended CONNECT streams to the existing tunnel path.

#### [medium] RFC 9218 Extensible Priorities (PRIORITY_UPDATE frame, Priority header) absent
**`include/proxy/http2/HTTP2.h:169`** · _missing-feature_

ATS implements only the deprecated RFC 7540 stream-priority tree (HTTP2_FRAME_TYPE_PRIORITY=2). There is no PRIORITY_UPDATE frame (type 0x10), no SETTINGS_NO_RFC7540_PRIORITIES, and no registered 'Priority' structured-field header token, so the urgency/incremental scheme that modern browsers actually send is ignored. Response scheduling cannot follow client-signaled RFC 9218 priorities.

```
HTTP2.h:169-180 frame-type enum runs DATA..CONTINUATION(9) with no PRIORITY_UPDATE; grep 'PRIORITY_UPDATE|urgency|incremental' in src/proxy/http2 and src/proxy/http3 finds only HPACK/test references; HdrToken.cc has no 'Priority' header token.
```

**Fix:** Parse the Priority request/response header and PRIORITY_UPDATE frames, and feed urgency/incremental into the H2/H3 stream scheduler.

#### [low] HTTP QUERY method (draft-safe-method-w-body) not a known method
**`src/proxy/hdrs/HdrToken.cc:113`** · _missing-feature_

The well-known method table omits QUERY. HTTP.cc likewise defines HTTP_METHOD_/HTTP_WKSIDX_ only for CONNECT, DELETE, GET, HEAD, OPTIONS, POST, PURGE, PUT, TRACE, PUSH. QUERY (a safe, cacheable method with a request body) is not recognized, so it cannot be treated as safe/cacheable and is handled as an unknown method rather than per the emerging spec.

```
HdrToken.cc:113 lists methods 'CONNECT, DELETE, GET, POST, HEAD, OPTIONS, PURGE, PUT, TRACE, PUSH' and :155-164 binds only those to HdrTokenType::METHOD; HTTP.cc:147-178 defines WKSIDX for the same ten only; grep '"QUERY"|HTTP_METHOD_QUERY' finds no method definition (only an unrelated HRW query-string component).
```

**Fix:** Register QUERY in the method token table and HTTP.cc WKSIDX list, and classify it as safe/cacheable for method-based cache decisions.

#### [low] RFC 9211 Cache-Status response header not generated
**`src/proxy/hdrs/HdrToken.cc:131`** · _missing-feature_

ATS does not emit an RFC 9211 Cache-Status structured-field header describing hit/miss/fwd/ttl. The only 'CacheStatus' in the tree is the internal plugin enum in tscpp/api (hit/miss codes), not a standardized on-the-wire header. Downstream caches/clients get no standardized cache-observability signal from ATS.

```
grep for 'Cache-Status' shows only src/tscpp/api Transaction::CacheStatus (an internal enum) and cache_promote debug strings; no MIME_FIELD_CACHE_STATUS token in HdrToken.cc and no header emission in HttpTransactHeaders.
```

**Fix:** Add a Cache-Status header token and emit an RFC 9211-formatted structured field on the client response summarizing the cache decision.

#### [low] No RFC 8941 Structured Fields parser
**`src/proxy/hdrs:1`** · _missing-feature_

There is no generic RFC 8941 structured-fields (item/list/dictionary) parser in the codebase. Header handling relies on ad hoc CSV tokenizers (HdrCsvIter) and per-field parsing. This absence is also the substrate that blocks clean implementation of Cache-Status, Priority, and other modern structured-field headers.

```
grep for 'structured.field|sf_parse|StructuredField|parse_dictionary|rfc8941' across src/include/lib returns no matches; Cache-Control/CDN-Cache-Control cooking in MIME.cc:3746+ uses HdrCsvIter and hand-rolled token scanning.
```

**Fix:** Introduce a reusable RFC 8941 parser/serializer in tsutil and migrate structured-field header handling to it.

#### [low] RFC 9111 must-understand cache directive not recognized
**`src/proxy/hdrs/MIME.cc:3746`** · _standards-gap_

The Cache-Control cooking logic has no token or cooked-mask for the must-understand directive, so ATS cannot apply RFC 9111 rule that a must-understand response may only be stored when its status code's caching semantics are understood. must-understand is silently ignored, which can lead to storing responses the origin intended to be cached only by understanding caches.

```
recompute_cooked_stuff (MIME.cc:3746-3796) tokenizes only known CC values via hdrtoken_tokenize with masks defined in MIME.h:214-227 (no must-understand); grep 'must.understand' across src/include returns nothing.
```

**Fix:** Add a must-understand token and gate storage of such responses on whether the response status code's cacheability is understood.

#### [low] TLS Encrypted Client Hello (ECH) not supported
**`src/iocore/net:1`** · _missing-feature_

There is no ECH (Encrypted Client Hello) support in the TLS layer: no SSL ECH config wiring, no ECHConfigList handling, no split-mode/backend ECH. (By contrast, TLS 0-RTT early data IS implemented via TLSEarlyDataSupport.) ATS cannot act as an ECH-terminating or client-facing server, leaving SNI exposed.

```
grep for 'encrypted_client_hello|ECHConfig|SSL_ech|OSSL_ECH|SSL_CTX_ech' across src/include/plugins returns no matches; 0-RTT is present at src/iocore/net/TLSEarlyDataSupport.cc:75-91 (SSL_set_max_early_data), confirming only early data, not ECH, is implemented.
```

**Fix:** Track OpenSSL/BoringSSL ECH APIs and add ECHConfig provisioning plus client-facing/backend ECH handling when the TLS stack supports it.


### Performance  (3 medium, 1 low)

_The remap and per-request setup paths are mostly well-optimized (accelerator-slot header lookups, stack buffers for host lowercasing, rank-bounded regex scans), but I confirmed several genuine hot-path performance issues. The headline is an avoidable per-request heap allocation in the remap host-table lookup: the URLTable is keyed by std::string but looked up with a char*, constructing a temporary std::string (heap alloc/free for hostnames past SSO) on essentially every remapped request — this exact bug was fixed upstream in the v11 tree via a transparent hasher. A second, broader issue is that the Metrics counters are single global std::atomic<int64_t> values with no per-thread sharding and no cache-line padding, so every request and every network read/write RMWs shared cache lines across all cores. The logging fast path also evaluates each header/string field twice per request (length pass then marshal pass), and check_sni_host builds a throwaway std::string per HTTPS request. Severities are medium and below; no crash/corruption issues were found in this lens._

#### [medium] Per-request std::string heap allocation in remap host-table lookup
**`src/proxy/http/remap/UrlRewrite.cc:303`** · _performance_ · _fix available: master #45 (transparent hasher)_

URLTable is declared as std::unordered_map<std::string, UrlMappingPathIndex *> (UrlRewrite.h:62), but _tableLookup calls h_table->find(request_host) where request_host is a char*. std::unordered_map::find with a non-key argument constructs a temporary std::string from the char* — a strlen plus a heap allocation/deallocation pair for any hostname longer than the libstdc++ 15-char SSO limit (i.e. most real FQDNs). _tableLookup runs on the primary hash mapping path of _mappingLookup, which is invoked for essentially every remapped request. The host is already NUL-terminated and its length is known (request_host_len is passed in and already used to lowercase it into request_host_lower), so the length is available without a rescan. The upstream v11 tree fixed exactly this by giving URLTable a transparent hasher (is_transparent) with std::equal_to<> and looking up via std::string_view{request_host, request_host_len}, eliminating the allocation.

```
src/proxy/http/remap/UrlRewrite.cc:303  `if (auto it = h_table->find(request_host); it != h_table->end()) {`  with request_host declared `char *request_host` (line 293-294) and key type `using URLTable = std::unordered_map<std::string, UrlMappingPathIndex *>;` (include/proxy/http/remap/UrlRewrite.h:62). Caller _mappingLookup already has request_host_len and passes request_host_lower (UrlRewrite.cc:924).
```

**Fix:** Give URLTable a transparent hasher (struct with `using is_transparent = void;` hashing std::string_view) and std::equal_to<>, then look up with std::string_view{request_host, static_cast<size_t>(request_host_len)}. This removes the per-request temporary std::string and its heap alloc/free.

#### [medium] Global atomic stat counters with no per-thread sharding contend on every request and IO
**`include/tsutil/Metrics.h:66`** · _performance_

Metrics::AtomicType wraps a single std::atomic<int64_t> and Metrics::Counter::increment does _value.fetch_add(val, relaxed) on it. All counters live in one process-wide std::array<AtomicType, MAX_SIZE> in the Metrics singleton (Metrics.h:102) — there is no per-thread sharding and AtomicType is 8 bytes with no cache-line padding, so ~8 unrelated counters share each 64-byte line. Every hot path increments these shared globals: net_read_io does three RMWs per recvmsg (calls_to_read, read_bytes, read_bytes_count), the write path does the same per send, and HttpSM increments http_rsb.incoming_requests (and others) per request. Because the same atomic and its neighbors are hammered by every event thread, this produces cache-line ping-pong (true sharing on the hot counter, false sharing on its line-mates) that serializes across cores at high connection counts and RPS. The relaxed ordering avoids fences but not the coherence traffic of a contended RMW. ATS's older raw-stat system deliberately used per-thread accumulation to avoid exactly this; the current design regresses to shared atomics.

```
include/tsutil/Metrics.h:64-66 `increment(int64_t val) { _value.fetch_add(val, MEMORY_ORDER); }` with `std::atomic<int64_t> _value{0};` (line 83), `MEMORY_ORDER = std::memory_order_relaxed` (line 94), storage `using AtomicStorage = std::array<AtomicType, MAX_SIZE>;` (line 102, single singleton instance). Hot increments: src/iocore/net/UnixNetVConnection.cc:542,574,575 (three per read), 628,716,717 (write); src/proxy/http/HttpSM.cc:463 (per request).
```

**Fix:** Shard counters per event thread and sum on read, or at minimum cache-line-align/pad the hottest per-IO counters so unrelated metrics stop false-sharing. Per-thread accumulation with lazy aggregation on scrape eliminates the cross-core RMW contention entirely.

#### [medium] Access-log fast path evaluates every header/string field twice per request
**`src/proxy/logging/LogObject.cc:645`** · _performance_

LogObject::log first calls m_format->m_field_list.marshal_len(lad) to size the entry, then after checking out buffer space calls m_format->m_field_list.marshal(lad, ...) to write it. For every non-integer field both passes run the identical accessor: LogField::marshal_len invokes the same marshal function with a nullptr buffer, and for header fields marshal_http_header_field performs a full HTTPHdr::field_find plus a walk over all duplicate fields on both the length pass (buf==nullptr) and the write pass (buf!=nullptr). So each %<{Header}> and string field in the log format triggers two field lookups and two dup-walks per logged request. With access logging enabled and a format containing several header fields this doubles the per-request marshalling work on the logging fast path. The double pass exists to size the buffer before checkout, but the length result is recomputed from scratch rather than cached from the first evaluation.

```
src/proxy/logging/LogObject.cc:645 `bytes_needed = m_format->m_field_list.marshal_len(lad);` then :683 `bytes_used = m_format->m_field_list.marshal(lad, &(*buffer)[offset]);`. LogField::marshal_len calls `(lad->*m_marshal_func)(nullptr)` / `lad->marshal_http_header_field(m_container, m_name, nullptr)` (src/proxy/logging/LogField.cc:525,537). marshal_http_header_field does `header->field_find(std::string_view{field})` and a `while (fld)` dup walk regardless of whether buf is null (src/proxy/logging/LogAccess.cc:3314-3343).
```

**Fix:** Have the length pass stash per-field computed values/lengths (e.g. into the LogAccess or a small per-request scratch) and reuse them in the marshal pass, or restructure to marshal into a thread-local scratch buffer once and copy the known length into the LogBuffer, so header field_find and dup walks run once per request.

#### [low] check_sni_host allocates a throwaway std::string per HTTPS request
**`src/proxy/http/HttpSM.cc:4609`** · _performance_

check_sni_host() runs on every request during do_remap_request. For TLS connections it calls snis->would_have_actions_for(std::string{host_name}.c_str(), ...), constructing a temporary std::string purely to NUL-terminate the host_name string_view for a const char* API. For hostnames longer than the SSO limit this is a heap alloc/free per HTTPS request, and it happens unconditionally before host_sni_policy is even known to be non-zero, so the cost is paid on every HTTPS request even when no SNI host policy is configured (the common case). would_have_actions_for additionally does an SNIConfig lookup with that string each time.

```
src/proxy/http/HttpSM.cc:4609 `if (snis->would_have_actions_for(std::string{host_name}.c_str(), netvc->get_remote_endpoint(), host_sni_policy) && host_sni_policy > 0) {` where host_name is a std::string_view over the client request host (line 4590). Called unconditionally from do_remap_request (HttpSM.cc:4651).
```

**Fix:** Change TLSSNISupport::would_have_actions_for to accept a std::string_view (it already has the length), or gate the call so the temporary/lookup is skipped when no host-SNI policy is configured. Avoids a per-HTTPS-request allocation and SNI table lookup in the default no-policy case.


### Code Quality & Maintainability  (4 medium, 4 low)

_The ATS 10.2.1 core is structurally healthy at the algorithm level but carries heavy size/maintainability debt. Quantitatively: src+include total ~371k lines; four files sit near 9-9.5k lines each (HttpTransact.cc 9430, InkAPI.cc 9331, InkAPITest.cc 9251, HttpSM.cc 9213). There are 309 TODO/FIXME/XXX markers (213 TODO, 33 FIXME, 40 XXX; zero HACK), 512 goto statements in src/*.cc, and 9 '#if 0' dead blocks. C-style memory management persists in a few spots despite the modern-C++20 RAII policy (raw malloc without null checks, goto-cleanup). The dominant issues are god-artifacts: HttpTransact.cc's 513-line handle_cache_operation_on_forward_server_response, the ~169-member HttpTransact::State god-struct, and oversized HttpSM dispatch functions. The one latent correctness concern is a raw malloc feeding fread with no null-check in the OCSP stapling path; the most alarming debt markers are disabled freelist alignment asserts and a header field-value validator commented as known-wrong._

#### [medium] HttpTransact.cc is a 9,430-line monolith with 500+ line god-functions
**`src/proxy/http/HttpTransact.cc:4495`** · _quality_

HttpTransact.cc is the single largest translation unit in the tree at 9,430 lines and concentrates nearly the entire HTTP forwarding/caching decision logic in one file. The worst offender within it is HttpTransact::handle_cache_operation_on_forward_server_response (513 lines, a single function spanning lines 4495-5008) built around an 18-case switch on server_response_code with deeply nested cache-action/next-state logic. Other functions in the same file exceed 200-350 lines (origin_server_connect_attempts_max_retries 356, client_result_stat 321, HandleCacheOpenReadHit 248, what_is_document_freshness 230). Functions this large are effectively untestable in isolation and are a chronic source of merge conflicts and subtle regressions.

```
HttpTransact::handle_cache_operation_on_forward_server_response(State *s)
{
  ... 513 lines, switch (server_response_code) { case HTTPStatus::NOT_MODIFIED: ... 18 case labels ... }
```

**Fix:** Extract per-status-code handling (304, 412, 5xx, 2xx) into named helper functions and split HttpTransact.cc along cache-vs-forwarding responsibilities. Prioritize decomposing handle_cache_operation_on_forward_server_response first.

#### [medium] HttpTransact::State is a ~169-member god-struct mixing every subsystem's transaction state
**`include/proxy/http/HttpTransact.h:664`** · _quality_

HttpTransact::State (lines 664-990, ~326 lines, ~169 member declarations) is a single flat struct that holds the entire per-transaction world: DNS state, cache action, ~40 boolean feature flags (api_cleanup_cache_read, api_server_response_no_store, transparent_passthrough, already_downgraded, skip_ip_allow_yaml, ...), header info, parent selection, an embedded Arena, plus the via_string char array. Every subsystem reads and writes arbitrary fields with no ownership boundaries, so any change to the flow risks stale-flag bugs and nothing localizes invariants. This is the canonical god-object the modern-C++ guidance warns against.

```
struct State {
    HttpSM *state_machine = nullptr;
    ...
    bool api_cleanup_cache_read = false;
    bool api_server_response_no_store = false;
    bool transparent_passthrough = false;
    bool already_downgraded = false;
    bool skip_ip_allow_yaml = false;   // ~40 bool flags among ~169 members, lines 664-990
```

**Fix:** Group cohesive sub-state (cache, DNS/hostdb, api-plugin flags, parent-selection) into nested structs with their own invariants; collapse the boolean flag soup into typed enums/bitset where flags are mutually related.

#### [medium] Freelist alignment safety assertions silently disabled with an unresolved XXX in ink_queue.cc
**`src/tscore/ink_queue.cc:328`** · _quality_

In the core lock-free freelist allocator, the alignment sanity assertion is commented out in both freelist_free (line 328) and freelist_bulkfree (line 393) with an unresolved developer note 'why is this no longer working? -bcall'. This is a safety check on a hot allocator path that was disabled rather than fixed, and the accompanying XXX has outlived the person who wrote it. A disabled invariant on the memory-allocation fast path is exactly the kind of latent corruption guard that should either be restored (correctly) or removed with a real explanation, not left as dead commented code that suggests the allocator's alignment contract is not actually enforced.

```
// ink_assert(!((long)item&(f->alignment-1))); XXX - why is this no longer working? -bcall   (appears at line 328 in freelist_free and line 393 in freelist_bulkfree)
```

**Fix:** Determine whether the alignment invariant still holds; if so restore a correct assert (accounting for whatever offset broke it), otherwise delete the commented line and document why alignment is not asserted here.

#### [medium] Raw malloc with no null-check feeding fread in OCSP stapling refresh path
**`src/iocore/net/OCSPStapling.cc:905`** · _memory-bug_

stapling_refresh_response reads a prefetched OCSP response file using raw C malloc/free with no null-check on the allocation before it is passed straight into fread. rsp_buf_len comes from ftell() on an attacker-influenceable/operator-supplied file path; a large file or allocation failure yields a null rsp_buf that fread() then dereferences, crashing the TLS-serving process. This also directly contradicts the project's stated RAII/modern-C++ policy in a security-sensitive networking file that otherwise uses ats_ allocators and smart pointers.

```
unsigned char *rsp_buf  = static_cast<unsigned char *>(malloc(rsp_buf_len));
auto           read_len = fread(rsp_buf, 1, rsp_buf_len, fp);  // rsp_buf never checked for nullptr
```

**Fix:** Use a std::vector<unsigned char>/std::unique_ptr sized to rsp_buf_len (with an upper bound), check the allocation, and drop the manual malloc/free + goto err cleanup.

#### [low] Pervasive goto-based error handling (512 gotos) inconsistent with the rest of the code
**`src/proxy/hdrs/HTTP.cc:1`** · _quality_

The codebase relies heavily on C-style goto err/goto done error handling: 512 goto statements across src/*.cc, concentrated in HTTP.cc (41), CacheRead.cc (39), RemapConfig.cc (28), SSLUtils.cc (24), CacheVC.cc (24), and OCSPStapling.cc (22). This coexists with functions that use return codes and others that use ink_release_assert, so error handling style is inconsistent across and even within subsystems. In C++20 with RAII available, the goto-cleanup idiom is both unnecessary and a frequent source of resource-leak-on-new-early-return bugs (as the OCSP finding shows, where malloc'd buffers depend on reaching the goto label).

```
grep -c '\bgoto\b' per file: HTTP.cc=41, CacheRead.cc=39, RemapConfig.cc=28, SSLUtils.cc=24, CacheVC.cc=24, OCSPStapling.cc=22 (512 total in src/*.cc)
```

**Fix:** Convert goto-cleanup functions to RAII scope guards / smart pointers incrementally, starting with the header and TLS parsers where the density is highest and the buffers are manually freed.

#### [low] High TODO/FIXME/XXX debt (309 markers) including a known-wrong header field-value validator
**`src/proxy/hdrs/MIME.cc:2561`** · _standards-gap_

src carries 309 TODO/FIXME/XXX markers (213 TODO, 33 FIXME, 40 XXX). The most concerning individual instance is in MIME header parsing: RFC 9110 field-value validation deliberately avoids the intended helper because 'the implementation looks wrong', falling back to a weaker is_control() check. A comment admitting the canonical validator (ParseRules::is_http_field_value) is broken, left in place on the request-header parsing path, is standards/security debt that has simply been routed around rather than fixed.

```
// FIXME: ParseRules::is_http_field_value() should be used but the implementation looks wrong
if (ParseRules::is_control(i)) {
  return ParseResult::ERROR;
}
```

**Fix:** Fix or replace ParseRules::is_http_field_value() to match RFC 9110 field-value grammar and use it here, then remove the FIXME; audit the other 33 FIXMEs for similar routed-around correctness gaps.

#### [low] InkAPI.cc / InkAPITest.cc are 9k+ line single files that dwarf reasonable module size
**`src/api/InkAPI.cc:1`** · _quality_

The plugin API layer is implemented and tested in two enormous single files: src/api/InkAPI.cc (9,331 lines) and src/api/InkAPITest.cc (9,251 lines). InkAPITest.cc in particular bundles the entire plugin-API regression suite into one translation unit, which makes selective test runs, code review, and locating a specific API's coverage impractical. Combined with HttpTransact.cc (9,430) and HttpSM.cc (9,213), four files each near 9-9.5k lines account for a large share of the proxy core's surface.

```
9331 src/api/InkAPI.cc
9251 src/api/InkAPITest.cc  (from wc -l; alongside HttpTransact.cc 9430 and HttpSM.cc 9213)
```

**Fix:** Split InkAPITest.cc into per-feature test files and InkAPI.cc along API domains (http txn, headers, cache, io buffers), which also parallelizes compilation.

#### [low] HttpSM.cc concentrates oversized state-handler functions (do_http_server_open 410 lines, set_next_state 389)
**`src/proxy/http/HttpSM.cc:5630`** · _quality_

The HTTP state machine's central dispatch functions are oversized: HttpSM::do_http_server_open (410 lines, line 5630) and HttpSM::set_next_state (389 lines) each embed the entire branching logic for their phase in one function, with state_read_client_request_header (277), redirect_request (224), and state_api_callout (214) close behind. set_next_state in particular is the routing hub of the whole SM, so its length makes the control flow of every request hard to follow and easy to break when adding a state. This is the same monolith pattern as HttpTransact but on the SM side.

```
HttpSM::do_http_server_open(bool raw, bool only_direct) — 410 lines (line 5630)
HttpSM::set_next_state() — 389 lines
```

**Fix:** Break set_next_state's per-state cases and do_http_server_open's connection-setup phases (pool lookup, transparency, TLS/plain, retry accounting) into named helpers so the top-level dispatch reads as a short switch.


### Tests & Documentation  (4 medium, 1 low)

_Under the test-coverage and documentation-health lens, the ATS 10.2.1 tree is reasonably strong in some areas (cache and HttpTransact have substantial unit tests) but has concrete gaps a maintainer should act on. The most impactful: the in-repo GitHub Actions CI that gates PRs runs no sanitizer build at all despite asan/tsan CMake presets existing (they are only wired to an external/dead Jenkins path), so memory and race regressions on the request path go undetected. Documentation drift is real — 53 live proxy.config records are undocumented, including current user-facing features (per-server connection metrics, HTTP/3 and QUIC tuning knobs, use_client_source_port). Core request-path code (HttpSM, HttpSessionManager, HttpCacheSM) and the async DNS resolver have essentially no unit tests, and the AuTest CI retry logic silently converts flaky failures into passing builds, hiding intermittent races rather than surfacing them._

#### [medium] Primary (GitHub Actions) CI runs no sanitizer build — ASAN/TSAN/UBSAN presets exist but are never invoked
**`.github/workflows/ci.yaml:176`** · _testing_

For a memory-unsafe C++20 network proxy, the in-repo CI that gates every PR (build+unit-test job, 4-shard AuTest job) compiles only with the plain `ci` preset — no AddressSanitizer, ThreadSanitizer, or UBSan. Sanitizer presets are defined but never referenced by any .github or ci/ script: CMakePresets.json defines an `asan` preset (line 92), a `tsan` preset (line 99), and a `ci-rocky` preset that inherits asan (line 172), yet ci.yaml uses `--preset ci` for build/unit-test (line 176) and AuTest (line 274), and `ci-docs` for docs (line 376); grep of .github/ and ci/ finds zero use of ci-rocky/asan/tsan presets. The only asan reference in the checked-in CI scripts is ci/jenkins/bin/build.sh line 33 using the autotools-era flag `--enable-asan`, which is dead after the v10 CMake migration. Result: use-after-free, buffer overflow, and data-race regressions on the request path can merge without any automated detection.

```
ci.yaml:176 `run: cmake -S . --preset ci -DENABLE_CRIPTS=ON`; ci.yaml:274 `run: cmake -S . --preset ci -DENABLE_AUTEST=ON -DENABLE_CRIPTS=ON`; CMakePresets.json:172 `"inherits": ["ci", "asan"]` (ci-rocky, unreferenced); grep of .github/ ci/ for ci-rocky/tsan presets returns nothing.
```

**Fix:** Add at least one CI job that builds with the asan preset and runs the unit tests (and ideally a subset of AuTests); add a periodic TSAN job for the event/threading code.

#### [medium] Many live proxy.config records are undocumented, including current user-facing features
**`src/records/RecordsConfig.cc:407`** · _docs_

53 of the 584 proxy.config.* records defined in RecordsConfig.cc appear nowhere under doc/admin-guide/. Several back real, wired-up, user-facing features, not just internal knobs: proxy.config.http.per_server.connection.metric_enabled (RecordsConfig.cc:407) and .metric_prefix are consumed by HttpConfig.cc / HttpSM.cc / ConnectionTracker.h yet have no admin docs; proxy.config.http.use_client_source_port (line 343) is a dynamic 0/1 toggle affecting outbound connections; the HTTP/3 tuning records proxy.config.http3.max_field_section_size (line 1434), .header_table_size, .qpack_blocked_streams, .num_placeholders, .max_settings and the QUIC records proxy.config.quic.disable_active_migration, .active_cid_limit_out, .server.quantum_readiness_test_enabled are all undocumented (grep of doc/ for quantum_readiness returns nothing). Operators cannot discover or safely tune these without reading source.

```
RecordsConfig.cc:407 `{RECT_CONFIG, "proxy.config.http.per_server.connection.metric_enabled", RECD_INT, "0", RECU_DYNAMIC, ...}`; RecordsConfig.cc:1434 `"proxy.config.http3.max_field_section_size", RECD_INT, "4096", ...` — neither string appears anywhere under doc/admin-guide/ (verified by grep of every record name against doc/admin-guide/).
```

**Fix:** Add ts:cv entries in doc/admin-guide/files/records.yaml.en.rst for the live records; the per-server connection metric and http3/quic tuning knobs are the highest priority since they are current features.

#### [medium] HttpSM (core request state machine) and session-reuse/cache-SM code have zero unit tests
**`src/proxy/http/HttpSM.cc:1`** · _testing_

src/proxy/http/HttpSM.cc is 9213 lines and is the central per-transaction state machine, yet src/proxy/http/unit_tests/ contains no test that instantiates or exercises HttpSM (grep for HttpSM across the unit_tests dir returns nothing). HttpSessionManager.cc (624 lines — origin connection pooling and keep-alive reuse, a classic source of cross-transaction bugs) and HttpCacheSM.cc (466 lines) likewise have no unit tests. Existing http unit tests cover HttpTransact logic, the ChunkedHandler, ForwardedConfig, and error-page selection, but the SM state transitions, tunnel wiring, and session-reuse matching are only ever exercised through end-to-end AuTests, which are coarse and cannot isolate the many state/branch combinations. This leaves the most bug-prone core with no fast, deterministic regression net.

```
`wc -l src/proxy/http/HttpSM.cc` = 9213; `grep -rln 'class HttpSM\|HttpSessionManager' src/proxy/http/unit_tests/` returns nothing; unit_tests dir contains only test_ChunkedHandler.cc, test_HttpTransact.cc, test_HttpTransactHeaders.cc, test_ForwardedConfig.cc, test_HttpUserAgent.cc, test_PreWarm.cc, test_error_page_selection.cc.
```

**Fix:** Introduce targeted unit tests for HttpSessionManager reuse/matching logic and for isolable HttpSM helpers; refactor to make SM sub-steps testable without a full network stack.

#### [medium] AuTest CI retry logic silently turns flaky failures into green builds
**`.github/workflows/ci.yaml:339`** · _testing_

The AuTest job runs the shard in parallel (-j2); on any failure it re-extracts the failed test names and re-runs them serially, and if that serial re-run passes the step exits successfully after emitting only a `::warning::` that the tests are 'flaky rather than broken'. Because the retry runs under `set -e` and its success is the step's final status, genuinely flaky end-to-end tests keep the job green and the flakiness is downgraded to a warning that no gate acts on. This hides intermittent races/timeouts (exactly the class of bug the missing sanitizer job would also catch) rather than surfacing them, so flaky tests accumulate undetected over releases.

```
ci.yaml:339-341 `echo "::warning::AuTest failures, retrying serially: ..."` / `bash ./autest.sh -j1 --sandbox /tmp/sb-retry -f $failed` / `echo "::warning::Passed on retry, so these are flaky rather than broken: ..."` — the serial retry's exit status becomes the step result, so a pass-on-retry yields a successful job.
```

**Fix:** Record flaky-on-retry outcomes as a tracked, non-passing signal (e.g. annotate + fail a dedicated advisory check, or open/update an issue) instead of collapsing them into a warning on a green build.

#### [low] Asynchronous DNS resolver has essentially no unit coverage
**`src/iocore/dns/unit_tests:1`** · _testing_

The DNS subsystem (DNSProcessor, DNSConnection, SRV handling, SplitDNS, retry/failover paths governed by proxy.config.dns.failover_number / failover_period) is a dedicated async resolver, but src/iocore/dns/unit_tests/ contains only test_HostEnt.cc plus CMakeLists.txt — a single small test of the HostEnt helper. None of the resolver state machine, response parsing, or failover logic is unit-tested; it is validated only indirectly via a few autests. Given DNS parsing operates on untrusted network data, the absence of parser/failover unit tests is a notable latent gap.

```
`ls src/iocore/dns/unit_tests/` = CMakeLists.txt, test_HostEnt.cc; proxy.config.dns.failover_number and proxy.config.dns.failover_period are also among the undocumented records in RecordsConfig.cc.
```

**Fix:** Add unit tests for DNS response parsing (including malformed/truncated packets) and for the failover/retry counters.

