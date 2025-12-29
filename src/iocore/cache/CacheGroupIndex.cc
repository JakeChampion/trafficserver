/** @file

  Cache Group Index Rebuilder Implementation

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include "CacheGroupIndex.h"
#include "P_CacheDoc.h"
#include "P_CacheHttp.h"
#include "P_CacheInternal.h"
#include "StripeSM.h"
#include "Stripe.h"

#include "iocore/eventsystem/EThread.h"
#include "iocore/eventsystem/EventProcessor.h"
#include "iocore/eventsystem/Lock.h"

#include "proxy/hdrs/HTTP.h"
#include "proxy/hdrs/MIME.h"

#include "tscore/Diags.h"
#include "tscore/ink_memory.h"

#include "tsutil/DbgCtl.h"

#include <cstring>
#include <unordered_set>

// Forward declaration for directory scanning helper (defined in CacheDir.cc)
int dir_bucket_loop_fix(Dir *start_dir, int s, Directory *directory);

namespace
{

DbgCtl dbg_ctl_cache_group_rebuild{"cache_group_rebuild"};

// Global rebuilder instance
CacheGroupIndexRebuilder *global_rebuilder = nullptr;

/**
 * Create a bitmap indicating which regions of a stripe contain data.
 *
 * This is similar to the make_vol_map function used by CacheVC::scanObject,
 * but optimized for the rebuilder's needs.
 *
 * @param stripe The stripe to scan
 * @return Allocated bitmap (caller must free with ats_free)
 */
char *
make_stripe_scan_map(Stripe *stripe)
{
  off_t  start_offset = stripe->vol_offset_to_offset(0);
  off_t  vol_len      = stripe->vol_relative_length(start_offset);
  size_t map_len      = (vol_len + (CacheGroupIndexRebuilder::SCAN_BUF_SIZE - 1)) / CacheGroupIndexRebuilder::SCAN_BUF_SIZE;
  char  *scan_map     = static_cast<char *>(ats_malloc(map_len));

  memset(scan_map, 0, map_len);

  // Scan directory entries to mark regions containing data
  for (int s = 0; s < stripe->directory.segments; s++) {
    Dir *seg = stripe->directory.get_segment(s);
    for (int b = 0; b < stripe->directory.buckets; b++) {
      Dir *e = dir_bucket(b, seg);
      if (dir_bucket_loop_fix(e, s, &stripe->directory)) {
        break;
      }
      while (e) {
        if (dir_offset(e) && stripe->dir_valid(e) && stripe->dir_agg_valid(e) && dir_head(e)) {
          off_t offset = stripe->vol_offset(e) - start_offset;
          if (offset >= 0 && offset < vol_len) {
            scan_map[offset / CacheGroupIndexRebuilder::SCAN_BUF_SIZE] = 1;
          }
        }
        e = next_dir(e, seg);
        if (!e) {
          break;
        }
      }
    }
  }

  return scan_map;
}

/**
 * Find the next region with data in the stripe.
 *
 * @param stripe The stripe being scanned
 * @param scan_map The bitmap of regions with data
 * @param offset Current offset in the stripe
 * @return Next offset with data, or end of stripe if none
 */
off_t
next_in_stripe_map(Stripe *stripe, char *scan_map, off_t offset)
{
  off_t start_offset = stripe->vol_offset_to_offset(0);
  off_t new_off      = offset - start_offset;
  off_t vol_len      = stripe->vol_relative_length(start_offset);

  while (new_off < vol_len && !scan_map[new_off / CacheGroupIndexRebuilder::SCAN_BUF_SIZE]) {
    new_off += CacheGroupIndexRebuilder::SCAN_BUF_SIZE;
  }

  if (new_off >= vol_len) {
    return vol_len + start_offset;
  }
  return new_off + start_offset;
}

} // anonymous namespace

////
// CacheGroupIndexRebuilder
//

CacheGroupIndexRebuilder::CacheGroupIndexRebuilder() : Continuation(new_ProxyMutex())
{
  SET_HANDLER(&CacheGroupIndexRebuilder::rebuild_event);

  // Initialize AIO callback
  _io.aiocb.aio_fildes = -1;
  _io.action           = nullptr;
  _io.thread           = AIO_CALLBACK_THREAD_ANY;
}

CacheGroupIndexRebuilder::~CacheGroupIndexRebuilder()
{
  stop();
}

void
CacheGroupIndexRebuilder::start()
{
  if (_running.exchange(true, std::memory_order_acq_rel)) {
    // Already running
    return;
  }

  Dbg(dbg_ctl_cache_group_rebuild, "Starting cache group index rebuild");

  _state              = State::START_STRIPE;
  _current_stripe_idx = -1;
  _stripes_scanned    = 0;
  _docs_scanned       = 0;
  _total_groups.store(0, std::memory_order_release);
  _total_memberships.store(0, std::memory_order_release);
  _complete.store(false, std::memory_order_release);
  _start_time = ink_get_hrtime();

  // Schedule the first event
  _trigger = eventProcessor.schedule_imm(this, ET_CALL);
}

void
CacheGroupIndexRebuilder::stop()
{
  if (!_running.exchange(false, std::memory_order_acq_rel)) {
    // Not running
    return;
  }

  Dbg(dbg_ctl_cache_group_rebuild, "Stopping cache group index rebuild");

  if (_trigger) {
    _trigger->cancel();
    _trigger = nullptr;
  }

  cleanup_stripe_scan();
  _state = State::IDLE;
}

int
CacheGroupIndexRebuilder::rebuild_event(int event, Event * /* e */)
{
  if (!_running.load(std::memory_order_acquire)) {
    return EVENT_DONE;
  }

  switch (_state) {
  case State::IDLE:
    return EVENT_DONE;

  case State::START_STRIPE:
    advance_to_next_stripe();
    if (_state == State::COMPLETE) {
      log_completion();
      _running.store(false, std::memory_order_release);
      _complete.store(true, std::memory_order_release);
      return EVENT_DONE;
    }
    if (!init_stripe_scan()) {
      // Failed to init, try next stripe
      _state   = State::START_STRIPE;
      _trigger = eventProcessor.schedule_imm(this, ET_CALL);
      return EVENT_CONT;
    }
    _state = State::SCANNING;
    // Fall through to SCANNING

  case State::SCANNING:
    if (!issue_read()) {
      // No more data in this stripe
      cleanup_stripe_scan();
      _state   = State::START_STRIPE;
      _trigger = eventProcessor.schedule_imm(this, ET_CALL);
      return EVENT_CONT;
    }
    _state = State::READ_PENDING;
    return EVENT_CONT;

  case State::READ_PENDING:
    // This state is reached when AIO completes
    if (event == AIO_EVENT_DONE) {
      if (!_io.ok()) {
        Dbg(dbg_ctl_cache_group_rebuild, "Read error on stripe %d, skipping to next", _current_stripe_idx);
        cleanup_stripe_scan();
        _state   = State::START_STRIPE;
        _trigger = eventProcessor.schedule_imm(this, ET_CALL);
        return EVENT_CONT;
      }
      _state = State::PROCESS_BUFFER;
    } else {
      // Spurious wakeup, wait for AIO
      return EVENT_CONT;
    }
    // Fall through to PROCESS_BUFFER

  case State::PROCESS_BUFFER: {
    int docs_processed  = process_buffer();
    _docs_scanned      += docs_processed;

    // Check if we should yield
    if (stripe_scan_complete()) {
      cleanup_stripe_scan();
      _state   = State::START_STRIPE;
      _trigger = eventProcessor.schedule_imm(this, ET_CALL);
    } else {
      _state = State::SCANNING;
      // Yield to avoid blocking - schedule with a small delay
      _trigger = eventProcessor.schedule_in(this, HRTIME_MSECONDS(YIELD_INTERVAL_MS), ET_CALL);
    }
    return EVENT_CONT;
  }

  case State::NEXT_STRIPE:
    // This state transitions back to START_STRIPE
    _state   = State::START_STRIPE;
    _trigger = eventProcessor.schedule_imm(this, ET_CALL);
    return EVENT_CONT;

  case State::COMPLETE:
    _running.store(false, std::memory_order_release);
    _complete.store(true, std::memory_order_release);
    return EVENT_DONE;
  }

  return EVENT_CONT;
}

bool
CacheGroupIndexRebuilder::init_stripe_scan()
{
  if (_current_stripe_idx < 0 || _current_stripe_idx >= gnstripes) {
    return false;
  }

  _current_stripe = gstripes[_current_stripe_idx];
  if (!_current_stripe) {
    return false;
  }

  Dbg(dbg_ctl_cache_group_rebuild, "Initializing scan for stripe %d: %s", _current_stripe_idx, _current_stripe->hash_text.get());

  // Create the scan map
  {
    CACHE_TRY_LOCK(lock, _current_stripe->mutex, this_ethread());
    if (!lock.is_locked()) {
      // Could not get lock, will retry
      return false;
    }
    _scan_map = make_stripe_scan_map(_current_stripe);
  }

  // Set up scan positions
  _scan_pos          = next_in_stripe_map(_current_stripe, _scan_map, _current_stripe->vol_offset_to_offset(0));
  _stripe_end        = _current_stripe->skip + _current_stripe->len;
  _offset            = 0;
  _fix_buffer_offset = 0;

  // Allocate I/O buffer
  _buf = new_IOBufferData(iobuffer_size_to_index(SCAN_BUF_SIZE, MAX_BUFFER_SIZE_INDEX), MEMALIGNED);

  return true;
}

bool
CacheGroupIndexRebuilder::issue_read()
{
  if (_scan_pos >= _stripe_end) {
    return false;
  }

  // Find next region with data
  _scan_pos = next_in_stripe_map(_current_stripe, _scan_map, _scan_pos);
  if (_scan_pos >= _stripe_end) {
    return false;
  }

  // Set up the AIO request
  _io.aiocb.aio_fildes = _current_stripe->fd;
  _io.aiocb.aio_offset = _scan_pos;
  _io.aiocb.aio_nbytes = SCAN_BUF_SIZE;

  // Ensure we don't read past the end of the stripe
  if (static_cast<off_t>(_io.aiocb.aio_offset + _io.aiocb.aio_nbytes) > _stripe_end) {
    _io.aiocb.aio_nbytes = _stripe_end - _io.aiocb.aio_offset;
  }

  _io.aiocb.aio_buf = _buf->data();
  _io.action        = this;
  _io.thread        = AIO_CALLBACK_THREAD_ANY;
  _offset           = 0;

  Dbg(dbg_ctl_cache_group_rebuild, "Reading stripe %d at offset %lld, %zu bytes", _current_stripe_idx,
      (long long)_io.aiocb.aio_offset, (size_t)_io.aiocb.aio_nbytes);

  ink_aio_read(&_io);
  return true;
}

int
CacheGroupIndexRebuilder::process_buffer()
{
  int docs_processed = 0;
  int max_docs       = MAX_DOCS_PER_YIELD;

  // Handle any fixup from partial object read
  if (_fix_buffer_offset) {
    _io.aio_result       += _fix_buffer_offset;
    _io.aiocb.aio_nbytes += _fix_buffer_offset;
    _io.aiocb.aio_offset -= _fix_buffer_offset;
    _io.aiocb.aio_buf     = static_cast<char *>(_io.aiocb.aio_buf) - _fix_buffer_offset;
    _fix_buffer_offset    = 0;
  }

  while (_offset < static_cast<int>(_io.aiocb.aio_nbytes) && docs_processed < max_docs) {
    Doc *doc = reinterpret_cast<Doc *>(_buf->data() + _offset);

    // Validate document magic
    if (doc->magic != DOC_MAGIC) {
      // Not a valid document, skip ahead
      _offset += CACHE_BLOCK_SIZE;
      continue;
    }

    // Check if we have the complete document header
    if (_offset + static_cast<int>(sizeof(Doc)) > static_cast<int>(_io.aiocb.aio_nbytes)) {
      // Partial document at end of buffer, need to handle overlap
      _fix_buffer_offset = _io.aiocb.aio_nbytes - _offset;
      break;
    }

    // Validate document length
    if (doc->len <= 0 || doc->len > static_cast<uint32_t>(_io.aiocb.aio_nbytes - _offset)) {
      // Invalid or truncated document
      _offset += CACHE_BLOCK_SIZE;
      continue;
    }

    // Only process first fragments (doc headers with HTTP info)
    if (doc->hlen > 0 && dir_head(reinterpret_cast<Dir *>(&doc->first_key))) {
      extract_and_index_groups(doc, _current_stripe);
      docs_processed++;
    }

    // Move to next document (round to cache block)
    _offset += _current_stripe->round_to_approx_size(doc->len);
  }

  // Update scan position for next read
  _scan_pos = _io.aiocb.aio_offset + _offset;

  return docs_processed;
}

void
CacheGroupIndexRebuilder::extract_and_index_groups(void *data, StripeSM *stripe)
{
  Doc *doc = static_cast<Doc *>(data);

  // Only HTTP documents have cache group information in headers
  if (doc->doc_type != CACHE_FRAG_TYPE_HTTP || doc->hlen == 0) {
    return;
  }

  // Try to unmarshal and extract HTTP info
  // We need to be careful here as the document may be from an old cache version
  CacheHTTPInfoVector info_vector;
  char               *hdr = doc->hdr();
  int                 len = doc->hlen;

  // Get handles to the alternate info without full unmarshal
  // This avoids allocating memory for the full HTTP headers
  uint32_t bytes_used = info_vector.get_handles(hdr, len, _buf.get());
  if (bytes_used == 0) {
    return;
  }

  // Track unique groups for statistics
  std::unordered_set<std::string> groups_found;

  // Iterate through alternates looking for cache group headers
  for (int i = 0; i < info_vector.count(); i++) {
    CacheHTTPInfo *alt = info_vector.get(i);
    if (!alt || !alt->valid()) {
      continue;
    }

    // Look for the X-Cache-Groups header in the response
    // This is where cache group memberships are typically stored
    HTTPHdr *response = alt->response_get();
    if (!response) {
      continue;
    }

    MIMEField *field = response->field_find(std::string_view("X-Cache-Groups"));
    while (field) {
      std::string_view value = field->value_get();
      if (!value.empty()) {
        // Parse comma-separated group names
        std::string groups_str(value);
        size_t      start = 0;
        size_t      end;

        while ((end = groups_str.find(',', start)) != std::string::npos) {
          std::string group = groups_str.substr(start, end - start);
          // Trim whitespace
          size_t trim_start = group.find_first_not_of(" \t");
          size_t trim_end   = group.find_last_not_of(" \t");
          if (trim_start != std::string::npos && trim_end != std::string::npos) {
            group = group.substr(trim_start, trim_end - trim_start + 1);
            if (!group.empty()) {
              groups_found.insert(group);
              // Add to stripe's group index
              {
                SCOPED_MUTEX_LOCK(lock, stripe->mutex, this_ethread());
                stripe->group_index_add(group, doc->first_key);
              }
              _total_memberships.fetch_add(1, std::memory_order_relaxed);
            }
          }
          start = end + 1;
        }

        // Handle last group (or only group if no commas)
        if (start < groups_str.length()) {
          std::string group      = groups_str.substr(start);
          size_t      trim_start = group.find_first_not_of(" \t");
          size_t      trim_end   = group.find_last_not_of(" \t");
          if (trim_start != std::string::npos && trim_end != std::string::npos) {
            group = group.substr(trim_start, trim_end - trim_start + 1);
            if (!group.empty()) {
              groups_found.insert(group);
              {
                SCOPED_MUTEX_LOCK(lock, stripe->mutex, this_ethread());
                stripe->group_index_add(group, doc->first_key);
              }
              _total_memberships.fetch_add(1, std::memory_order_relaxed);
            }
          }
        }
      }

      // Check for additional X-Cache-Groups fields
      field = field->m_next_dup;
    }
  }

  // Update unique group count
  _total_groups.fetch_add(static_cast<int>(groups_found.size()), std::memory_order_relaxed);

  // Clear the vector without deallocating the alternates (we don't own them)
  info_vector.clear(false);
}

void
CacheGroupIndexRebuilder::advance_to_next_stripe()
{
  _current_stripe_idx++;

  if (_current_stripe_idx >= gnstripes) {
    _state = State::COMPLETE;
    return;
  }

  Dbg(dbg_ctl_cache_group_rebuild, "Advancing to stripe %d of %d", _current_stripe_idx + 1, gnstripes.load());
}

bool
CacheGroupIndexRebuilder::stripe_scan_complete() const
{
  return _scan_pos >= _stripe_end;
}

void
CacheGroupIndexRebuilder::cleanup_stripe_scan()
{
  if (_scan_map) {
    ats_free(_scan_map);
    _scan_map = nullptr;
  }

  _buf.clear();
  _current_stripe    = nullptr;
  _scan_pos          = 0;
  _stripe_end        = 0;
  _offset            = 0;
  _fix_buffer_offset = 0;
  _stripes_scanned++;
}

void
CacheGroupIndexRebuilder::log_completion()
{
  ink_hrtime elapsed     = ink_get_hrtime() - _start_time;
  double     elapsed_sec = static_cast<double>(elapsed) / HRTIME_SECOND;

  Note("Cache group index rebuild complete: %d groups, %d memberships, %d stripes, %d docs in %.2f seconds",
       _total_groups.load(std::memory_order_acquire), _total_memberships.load(std::memory_order_acquire), _stripes_scanned,
       _docs_scanned, elapsed_sec);
}

////
// Global functions
//

void
cache_group_index_rebuild_start()
{
  if (global_rebuilder) {
    return;
  }

  global_rebuilder = new CacheGroupIndexRebuilder();
  global_rebuilder->start();
}

void
cache_group_index_rebuild_stop()
{
  if (!global_rebuilder) {
    return;
  }

  global_rebuilder->stop();
  delete global_rebuilder;
  global_rebuilder = nullptr;
}

bool
cache_group_index_rebuild_complete()
{
  if (!global_rebuilder) {
    return true; // No rebuilder means nothing to rebuild
  }

  return global_rebuilder->is_complete();
}

CacheGroupIndexRebuilder *
get_cache_group_index_rebuilder()
{
  return global_rebuilder;
}
