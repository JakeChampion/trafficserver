/** @file

  Cache Group Index Rebuilder

  This module provides a background index rebuilder for cache groups.
  When ATS starts, the group index is empty because it's not persisted
  to disk. The CacheGroupIndexRebuilder scans cached objects in the
  background to rebuild the index, enabling group-based invalidation
  even after restart.

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

#pragma once

#include "iocore/aio/AIO.h"
#include "iocore/eventsystem/Continuation.h"
#include "iocore/eventsystem/Event.h"
#include "iocore/eventsystem/IOBuffer.h"

#include "tscore/ink_hrtime.h"

#include <atomic>
#include <cstdint>

class StripeSM;

/**
 * Background scanner that rebuilds the cache group index at startup.
 *
 * The CacheGroupIndexRebuilder is a Continuation-based background worker
 * that scans all cache stripes to rebuild the in-memory group index.
 * This allows group-based cache invalidation to work correctly even
 * after ATS restarts.
 *
 * Startup sequence:
 * 1. ATS starts accepting traffic immediately (index is empty)
 * 2. This background thread begins scanning cache stripes
 * 3. Index is populated incrementally as documents are scanned
 * 4. NOTE logged when rebuild is complete
 * 5. Invalidations during rebuild may be incomplete (documented limitation)
 *
 * The rebuilder processes one stripe at a time, yielding periodically
 * to avoid blocking the event thread. It reads document headers to
 * extract cache group information and adds entries to the stripe's
 * group index.
 */
class CacheGroupIndexRebuilder : public Continuation
{
public:
  /**
   * Constructor for CacheGroupIndexRebuilder.
   *
   * Creates a new rebuilder instance. Call start() to begin the
   * background rebuild process.
   */
  CacheGroupIndexRebuilder();

  /**
   * Destructor for CacheGroupIndexRebuilder.
   */
  ~CacheGroupIndexRebuilder() override;

  /**
   * Start the background index rebuild process.
   *
   * Schedules the rebuilder to begin scanning stripes. The rebuild
   * runs in the background and does not block normal cache operations.
   */
  void start();

  /**
   * Stop the background index rebuild process.
   *
   * Cancels any pending operations and stops the rebuild. The index
   * will remain in its current partially-rebuilt state.
   */
  void stop();

  /**
   * Check if the rebuild is complete.
   *
   * @return true if all stripes have been scanned
   */
  bool
  is_complete() const
  {
    return _complete.load(std::memory_order_acquire);
  }

  /**
   * Check if the rebuilder is currently running.
   *
   * @return true if the rebuild is in progress
   */
  bool
  is_running() const
  {
    return _running.load(std::memory_order_acquire);
  }

  /**
   * Get the total number of groups discovered.
   *
   * @return count of unique groups found during rebuild
   */
  int
  total_groups() const
  {
    return _total_groups.load(std::memory_order_acquire);
  }

  /**
   * Get the total number of group memberships discovered.
   *
   * @return count of key-to-group associations found
   */
  int
  total_memberships() const
  {
    return _total_memberships.load(std::memory_order_acquire);
  }

  /**
   * Get the index of the current stripe being scanned.
   *
   * @return current stripe index, or -1 if not scanning
   */
  int
  current_stripe_index() const
  {
    return _current_stripe_idx;
  }

  // Configuration constants - public so helper functions can access them
  static constexpr int SCAN_BUF_SIZE      = 8 * 1024 * 1024; // 8MB scan buffer
  static constexpr int YIELD_INTERVAL_MS  = 10;              // Yield every 10ms
  static constexpr int MAX_DOCS_PER_YIELD = 1000;            // Max docs before yielding

private:
  /**
   * State machine states for the rebuilder.
   */
  enum class State {
    IDLE,           ///< Not running
    START_STRIPE,   ///< Starting to scan a new stripe
    SCANNING,       ///< Actively scanning a stripe
    READ_PENDING,   ///< Waiting for async I/O to complete
    PROCESS_BUFFER, ///< Processing read buffer
    NEXT_STRIPE,    ///< Moving to the next stripe
    COMPLETE        ///< Rebuild finished
  };

  /**
   * Main event handler for the rebuilder.
   *
   * Implements a state machine that:
   * 1. Iterates through all cache stripes
   * 2. For each stripe, scans directory entries
   * 3. Reads document headers to extract group information
   * 4. Updates the stripe's group index
   * 5. Yields periodically to avoid blocking
   *
   * @param event The event code
   * @param data Event data (may be AIOCallback for I/O completion)
   * @return EVENT_CONT to continue, EVENT_DONE when complete
   */
  int rebuild_event(int event, Event *data);

  /**
   * Initialize scanning for a new stripe.
   *
   * Sets up the scan position and creates the scan map for the stripe.
   *
   * @return true if stripe initialization succeeded
   */
  bool init_stripe_scan();

  /**
   * Issue an async read for the next block of the stripe.
   *
   * @return true if a read was issued, false if scan is complete
   */
  bool issue_read();

  /**
   * Process the read buffer and extract group information.
   *
   * Scans the buffer for valid document headers and extracts
   * cache group names from HTTP info structures.
   *
   * @return number of documents processed
   */
  int process_buffer();

  /**
   * Extract cache groups from a document and add to index.
   *
   * @param doc Pointer to the document header
   * @param stripe The stripe containing the document
   */
  void extract_and_index_groups(void *doc, StripeSM *stripe);

  /**
   * Move to the next stripe or complete the rebuild.
   */
  void advance_to_next_stripe();

  /**
   * Check if the current stripe scan is complete.
   *
   * @return true if all data in the current stripe has been scanned
   */
  bool stripe_scan_complete() const;

  /**
   * Clean up resources for the current stripe scan.
   */
  void cleanup_stripe_scan();

  /**
   * Log completion statistics.
   */
  void log_completion();

  // State tracking
  State             _state{State::IDLE};
  std::atomic<bool> _running{false};
  std::atomic<bool> _complete{false};
  Event            *_trigger{nullptr};

  // Stripe scanning state
  int       _current_stripe_idx{-1};
  StripeSM *_current_stripe{nullptr};
  char     *_scan_map{nullptr};
  off_t     _scan_pos{0};
  off_t     _stripe_end{0};

  // I/O state
  AIOCallback       _io;
  Ptr<IOBufferData> _buf;
  int               _offset{0};
  off_t             _fix_buffer_offset{0};

  // Statistics
  std::atomic<int> _total_groups{0};
  std::atomic<int> _total_memberships{0};
  int              _stripes_scanned{0};
  int              _docs_scanned{0};
  ink_hrtime       _start_time{0};
};

/**
 * Start the background cache group index rebuild.
 *
 * This should be called after the cache is initialized and ready.
 * The rebuild runs in the background and does not block cache operations.
 */
void cache_group_index_rebuild_start();

/**
 * Stop the background cache group index rebuild.
 *
 * This should be called during cache shutdown.
 */
void cache_group_index_rebuild_stop();

/**
 * Check if the cache group index rebuild is complete.
 *
 * @return true if the rebuild has finished
 */
bool cache_group_index_rebuild_complete();

/**
 * Get the global CacheGroupIndexRebuilder instance.
 *
 * @return Pointer to the global rebuilder, or nullptr if not initialized
 */
CacheGroupIndexRebuilder *get_cache_group_index_rebuilder();
