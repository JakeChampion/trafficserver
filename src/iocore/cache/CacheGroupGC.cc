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

#include "CacheGroupGC.h"
#include "P_CacheInternal.h"
#include "StripeSM.h"

#include "iocore/eventsystem/EThread.h"
#include "iocore/eventsystem/EventProcessor.h"

#include "tsutil/DbgCtl.h"

#include <algorithm>
#include <vector>

namespace
{

DbgCtl dbg_ctl_cache_groups{"cache_groups"};

// Configuration: GC interval in seconds (default: 60 seconds)
// This could be made configurable via records.yaml in the future
constexpr int CACHE_GROUP_GC_INTERVAL_SECONDS = 60;

// Maximum number of groups to process per GC event to avoid blocking
constexpr int CACHE_GROUP_GC_BATCH_SIZE = 100;

} // end anonymous namespace

CacheGroupGC *CacheGroupGC::_instance = nullptr;

CacheGroupGC::CacheGroupGC() : Continuation(new_ProxyMutex())
{
  SET_HANDLER(&CacheGroupGC::gc_event);
}

CacheGroupGC *
CacheGroupGC::instance()
{
  return _instance;
}

void
CacheGroupGC::init()
{
  if (_instance != nullptr) {
    return; // Already initialized
  }

  _instance          = new CacheGroupGC();
  _instance->trigger = eventProcessor.schedule_in(_instance, HRTIME_SECONDS(CACHE_GROUP_GC_INTERVAL_SECONDS));
  Dbg(dbg_ctl_cache_groups, "Cache group GC initialized, interval=%d seconds", CACHE_GROUP_GC_INTERVAL_SECONDS);
}

int
CacheGroupGC::gc_event(int event, Event *e)
{
  // Cancel any pending trigger
  if (trigger) {
    trigger->cancel_action();
    trigger = nullptr;
  }

  // Check if we're starting a new GC cycle
  if (stripe_index == 0) {
    keys_removed   = 0;
    groups_removed = 0;
    Dbg(dbg_ctl_cache_groups, "Starting cache group GC cycle");
  }

  // Process stripes
  int processed_groups = 0;

  while (stripe_index < gnstripes && processed_groups < CACHE_GROUP_GC_BATCH_SIZE) {
    StripeSM *stripe = gstripes[stripe_index];

    // Try to acquire the stripe lock
    CACHE_TRY_LOCK(lock, stripe->mutex, mutex->thread_holding);
    if (!lock.is_locked()) {
      // Could not acquire lock, try again later
      Dbg(dbg_ctl_cache_groups, "GC could not acquire lock for stripe %d, will retry", stripe_index);
      break;
    }

    // Check if stripe has a group index
    if (stripe->group_index_empty()) {
      ++stripe_index;
      continue;
    }

    // Get all group names (so we can iterate without holding index)
    std::vector<std::string> group_names = stripe->group_index_get_groups();

    // Collect groups to remove after cleanup
    std::vector<std::string> groups_to_remove;

    for (const auto &group : group_names) {
      if (processed_groups >= CACHE_GROUP_GC_BATCH_SIZE) {
        break;
      }

      // Clean up stale keys from this group
      size_t removed  = stripe->group_index_cleanup(group);
      keys_removed   += removed;

      if (removed > 0) {
        Dbg(dbg_ctl_cache_groups, "GC removed %zu stale keys from group '%s'", removed, group.c_str());
      }

      // Check if group is now empty and should be removed
      std::vector<CacheKey> members = stripe->group_index_get_members(group);
      if (members.empty()) {
        groups_to_remove.push_back(group);
        Dbg(dbg_ctl_cache_groups, "GC marking empty group '%s' for removal", group.c_str());
      }

      ++processed_groups;
    }

    // Remove empty groups
    for (const auto &group : groups_to_remove) {
      stripe->group_index_remove_group(group);
      ++groups_removed;
    }

    // Move to next stripe if we've processed all groups in this one
    // or if we haven't hit the batch limit
    if (processed_groups < CACHE_GROUP_GC_BATCH_SIZE) {
      ++stripe_index;
    }
  }

  // Check if GC cycle is complete
  if (stripe_index >= gnstripes) {
    Dbg(dbg_ctl_cache_groups, "Cache group GC cycle complete: removed %d stale keys, %d empty groups", keys_removed,
        groups_removed);
    stripe_index = 0;
  }

  // Schedule next GC event
  if (event == EVENT_INTERVAL) {
    trigger = e->ethread->schedule_in(this, HRTIME_SECONDS(CACHE_GROUP_GC_INTERVAL_SECONDS));
  } else {
    trigger = eventProcessor.schedule_in(this, HRTIME_SECONDS(CACHE_GROUP_GC_INTERVAL_SECONDS));
  }

  return EVENT_CONT;
}

void
lazy_cleanup_group(StripeSM *stripe, const std::string &group)
{
  if (stripe == nullptr) {
    return;
  }

  // Use the accessor method to clean up stale keys
  size_t removed = stripe->group_index_cleanup(group);
  if (removed > 0) {
    Dbg(dbg_ctl_cache_groups, "Lazy cleanup removed %zu stale keys from group '%s'", removed, group.c_str());
  }

  // If the group is now empty, we leave it for the periodic GC to clean up
}
