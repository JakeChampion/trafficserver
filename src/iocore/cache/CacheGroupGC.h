/** @file

  Cache Groups Garbage Collection

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

#include "iocore/cache/CacheDefs.h"

#include <string>

class StripeSM;

/**
 * Cache Groups Garbage Collector.
 *
 * This class implements both periodic and lazy garbage collection for the
 * cache groups index. The periodic GC runs on a configurable interval to
 * sweep through all stripes and remove stale index entries for objects that
 * have been evicted or expired. The lazy cleanup mechanism is called when
 * accessing groups during invalidation operations.
 *
 * Key features:
 * - Periodic sweep of all stripes to remove stale entries
 * - Removes keys for expired/evicted objects by probing the directory
 * - Removes empty groups from the index
 * - Configurable GC interval
 * - Uses debug tag "cache_groups" for logging
 *
 * The GC is designed to work in conjunction with the cache groups feature
 * as specified in RFC 9875 (HTTP Cache Groups).
 */
class CacheGroupGC : public Continuation
{
public:
  CacheGroupGC();

  /**
   * Main event handler for periodic GC.
   *
   * This method is called periodically by the event system to perform
   * garbage collection on the cache groups index.
   *
   * @param event The event type (typically EVENT_INTERVAL)
   * @param e The Event object
   * @return EVENT_CONT to continue periodic scheduling
   */
  int gc_event(int event, Event *e);

  /**
   * Get the singleton instance of the garbage collector.
   *
   * @return Pointer to the singleton CacheGroupGC instance, or nullptr if not initialized
   */
  static CacheGroupGC *instance();

  /**
   * Initialize the garbage collector.
   *
   * Creates the singleton instance and schedules the first GC event.
   * Should be called during cache initialization after stripes are ready.
   */
  static void init();

private:
  Event *trigger = nullptr; ///< Event trigger for periodic scheduling
  int    stripe_index{0};   ///< Current stripe being processed
  int    keys_removed{0};   ///< Count of keys removed in current GC cycle
  int    groups_removed{0}; ///< Count of empty groups removed in current GC cycle

  static CacheGroupGC *_instance;
};

/**
 * Lazy cleanup for a specific group during invalidation.
 *
 * This function removes stale keys from a group index by probing the
 * directory to check if each cached object still exists. It is called
 * during group access operations (such as invalidation) to clean up
 * any entries that refer to objects that have been evicted or expired.
 *
 * @param stripe The stripe containing the group index
 * @param group The group name to clean up
 */
void lazy_cleanup_group(StripeSM *stripe, const std::string &group);
