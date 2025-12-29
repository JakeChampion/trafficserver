/** @file

  Cache Group Invalidation Worker

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

#include "iocore/eventsystem/Continuation.h"
#include "iocore/eventsystem/Event.h"

#include "tscore/CryptoHash.h"
#include "tscore/ink_mutex.h"
#include "tscore/List.h"

#include <queue>
#include <string>
#include <vector>

class StripeSM;

/**
 * Represents a unit of work for group invalidation.
 *
 * This structure holds the information needed to invalidate all cache entries
 * belonging to a specific cache group, optionally filtered by origin.
 */
struct GroupInvalidationWork {
  std::string group_name; ///< Name of the cache group to invalidate
  std::string origin;     ///< Optional origin filter (empty means all origins)

  GroupInvalidationWork() = default;
  GroupInvalidationWork(std::string group, std::string orig = "") : group_name(std::move(group)), origin(std::move(orig)) {}
};

/**
 * Async background worker that processes cache group invalidation requests.
 *
 * The CacheGroupInvalidator is a Continuation-based worker that periodically
 * processes invalidation work items from the queue. It handles:
 *
 * 1. Looking up all cache keys belonging to a group
 * 2. Optionally filtering by origin
 * 3. Removing entries from RAM cache
 * 4. Removing entries from disk cache
 * 5. Updating the group index
 *
 * The worker processes items in batches to avoid blocking for too long.
 */
class CacheGroupInvalidator : public Continuation
{
public:
  /**
   * Constructor for CacheGroupInvalidator.
   *
   * Creates a new invalidator instance. Call start() to begin processing.
   */
  CacheGroupInvalidator();

  /**
   * Start the invalidation worker.
   *
   * Schedules the worker to periodically check for and process
   * invalidation work items.
   */
  void start();

  /**
   * Stop the invalidation worker.
   *
   * Cancels any pending events and stops processing. Any queued
   * work items will be discarded.
   */
  void stop();

  /**
   * Queue a group invalidation request.
   *
   * This function is thread-safe and can be called from any thread.
   * The actual invalidation work will be performed asynchronously
   * by the worker.
   *
   * @param group_name Name of the cache group to invalidate
   * @param origin Optional origin to filter by (empty string means all origins)
   */
  void queue_invalidation(const std::string &group_name, const std::string &origin = "");

  /**
   * Get the number of pending invalidation requests.
   *
   * @return Number of work items in the queue
   */
  size_t pending_count() const;

private:
  /**
   * Main event handler for the invalidator.
   *
   * Called periodically by the event system to process queued work items.
   *
   * @param event The event code
   * @param e The event data
   * @return EVENT_CONT to continue processing, EVENT_DONE when complete
   */
  int invalidation_event(int event, Event *e);

  /**
   * Remove a key from the RAM cache.
   *
   * @param stripe The stripe containing the key
   * @param key The cache key to remove
   */
  void ram_cache_remove(StripeSM *stripe, const CryptoHash &key);

  /**
   * Queue a key for async disk removal.
   *
   * @param stripe The stripe containing the key
   * @param key The cache key to remove
   */
  void queue_disk_remove(StripeSM *stripe, const CryptoHash &key);

  std::queue<GroupInvalidationWork> _work_queue;           ///< Queue of pending invalidation work
  mutable ink_mutex                 _queue_mutex;          ///< Mutex protecting the work queue
  Event                            *_trigger    = nullptr; ///< Scheduled event for periodic processing
  bool                              _running    = false;   ///< Whether the worker is running
  int                               _batch_size = 100;     ///< Number of items to process per tick
};

/**
 * Global function to queue a group invalidation request.
 *
 * This is a convenience function that queues an invalidation request
 * to the global CacheGroupInvalidator instance.
 *
 * @param group_name Name of the cache group to invalidate
 * @param origin Optional origin to filter by (empty string means all origins)
 */
void queue_group_invalidation(const std::string &group_name, const std::string &origin = "");

/**
 * Initialize the cache group invalidation subsystem.
 *
 * Creates and starts the global CacheGroupInvalidator. This should be
 * called during cache initialization.
 */
void cache_group_invalidation_init();

/**
 * Shutdown the cache group invalidation subsystem.
 *
 * Stops the global CacheGroupInvalidator. This should be called
 * during cache shutdown.
 */
void cache_group_invalidation_shutdown();

/**
 * Get the global CacheGroupInvalidator instance.
 *
 * @return Pointer to the global invalidator, or nullptr if not initialized
 */
CacheGroupInvalidator *get_cache_group_invalidator();
