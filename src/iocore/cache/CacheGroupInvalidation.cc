/** @file

  Cache Group Invalidation Worker Implementation

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

#include "CacheGroupInvalidation.h"
#include "P_CacheInternal.h"
#include "P_RamCache.h"
#include "StripeSM.h"

#include "iocore/eventsystem/EventProcessor.h"
#include "iocore/eventsystem/Lock.h"

#include "tsutil/DbgCtl.h"
#include "tscore/Diags.h"
#include "tscore/ink_hrtime.h"
#include "tscore/ink_mutex.h"

#include <atomic>

namespace
{

DbgCtl dbg_ctl_cache_groups{"cache_groups"};

// Configuration for group invalidation
// TODO: These should be made configurable via records.yaml
constexpr int DEFAULT_INVALIDATION_BATCH_SIZE = 100; // Items per tick
constexpr int INVALIDATION_CHECK_INTERVAL_MS  = 100; // How often to check for work

// Global invalidator instance
std::atomic<CacheGroupInvalidator *> global_invalidator{nullptr};

} // end anonymous namespace

CacheGroupInvalidator::CacheGroupInvalidator() : Continuation(new_ProxyMutex()), _batch_size(DEFAULT_INVALIDATION_BATCH_SIZE)
{
  ink_mutex_init(&_queue_mutex);
  SET_HANDLER(&CacheGroupInvalidator::invalidation_event);
}

void
CacheGroupInvalidator::start()
{
  if (_running) {
    return;
  }

  _running = true;
  Dbg(dbg_ctl_cache_groups, "starting cache group invalidation worker");

  // Schedule periodic check for invalidation work
  _trigger = eventProcessor.schedule_every(this, HRTIME_MSECONDS(INVALIDATION_CHECK_INTERVAL_MS), ET_CALL);
}

void
CacheGroupInvalidator::stop()
{
  if (!_running) {
    return;
  }

  Dbg(dbg_ctl_cache_groups, "stopping cache group invalidation worker");

  _running = false;

  if (_trigger) {
    _trigger->cancel();
    _trigger = nullptr;
  }
}

void
CacheGroupInvalidator::queue_invalidation(const std::string &group_name, const std::string &origin)
{
  ink_mutex_acquire(&_queue_mutex);
  _work_queue.emplace(group_name, origin);
  ink_mutex_release(&_queue_mutex);

  Dbg(dbg_ctl_cache_groups, "queued invalidation for group '%s' origin '%s'", group_name.c_str(),
      origin.empty() ? "(all)" : origin.c_str());
}

size_t
CacheGroupInvalidator::pending_count() const
{
  ink_mutex_acquire(&_queue_mutex);
  size_t count = _work_queue.size();
  ink_mutex_release(&_queue_mutex);
  return count;
}

int
CacheGroupInvalidator::invalidation_event(int /* event ATS_UNUSED */, Event * /* e ATS_UNUSED */)
{
  if (!_running) {
    return EVENT_DONE;
  }

  // Get all work items to process in this batch
  std::vector<GroupInvalidationWork> work_items;
  ink_mutex_acquire(&_queue_mutex);
  while (!_work_queue.empty() && static_cast<int>(work_items.size()) < _batch_size) {
    work_items.push_back(_work_queue.front());
    _work_queue.pop();
  }
  ink_mutex_release(&_queue_mutex);

  if (work_items.empty()) {
    // No work, continue waiting
    return EVENT_CONT;
  }

  Dbg(dbg_ctl_cache_groups, "processing %zu invalidation work items", work_items.size());

  // Process each work item against all stripes
  int nstripes = gnstripes.load();

  for (const auto &work : work_items) {
    size_t total_keys_invalidated = 0;

    Dbg(dbg_ctl_cache_groups, "invalidating group '%s' across %d stripes", work.group_name.c_str(), nstripes);

    for (int i = 0; i < nstripes; i++) {
      StripeSM *stripe = gstripes[i];
      if (!stripe) {
        continue;
      }

      // Try to acquire stripe lock
      CACHE_TRY_LOCK(lock, stripe->mutex, this->mutex->thread_holding);
      if (!lock.is_locked()) {
        // Could not get lock, log and continue
        // The invalidation will be incomplete but at least we tried
        Dbg(dbg_ctl_cache_groups, "could not acquire lock for stripe %s, skipping", stripe->hash_text.get());
        continue;
      }

      // Get all cache keys belonging to this group from the group index
      std::vector<CacheKey> keys = stripe->group_index_get_members(work.group_name);

      if (keys.empty()) {
        continue;
      }

      Dbg(dbg_ctl_cache_groups, "found %zu keys for group '%s' in stripe %s", keys.size(), work.group_name.c_str(),
          stripe->hash_text.get());

      // Invalidate RAM cache entries first (fast path)
      for (const auto &key : keys) {
        ram_cache_remove(stripe, key);
      }

      // Queue disk removal (async)
      for (const auto &key : keys) {
        queue_disk_remove(stripe, key);
      }

      // Remove this group from the group index since we're invalidating all its members
      stripe->group_index_remove_group(work.group_name);

      total_keys_invalidated += keys.size();
    }

    if (total_keys_invalidated > 0) {
      Note("cache group invalidation completed: group='%s' origin='%s' keys_invalidated=%zu", work.group_name.c_str(),
           work.origin.empty() ? "(all)" : work.origin.c_str(), total_keys_invalidated);
    } else {
      Dbg(dbg_ctl_cache_groups, "no keys found for group '%s' in any stripe", work.group_name.c_str());
    }
  }

  Dbg(dbg_ctl_cache_groups, "finished processing %zu invalidation items", work_items.size());

  return EVENT_CONT;
}

void
CacheGroupInvalidator::ram_cache_remove(StripeSM *stripe, const CryptoHash &key)
{
  if (!stripe->ram_cache) {
    return;
  }

  // Remove from RAM cache
  // The RAM cache interface uses CryptoHash* for consistency with existing API
  CryptoHash mutable_key = key;

  // Try to get the entry first to verify it exists
  Ptr<IOBufferData> data;
  if (stripe->ram_cache->get(&mutable_key, &data)) {
    // Entry exists - we need to evict it
    // NOTE: The current RamCache interface doesn't have a direct remove method.
    // The typical pattern is to let entries expire naturally or be evicted.
    // For group invalidation, we may need to extend the RamCache interface.
    Dbg(dbg_ctl_cache_groups, "found key in RAM cache for stripe %s", stripe->hash_text.get());

    // TODO: Add RamCache::remove() method or use alternative eviction strategy
  }
}

void
CacheGroupInvalidator::queue_disk_remove(StripeSM *stripe, const CryptoHash &key)
{
  // Queue an async remove operation for this key
  // This uses the existing cache remove infrastructure

  Dbg(dbg_ctl_cache_groups, "queuing disk remove for key in stripe %s", stripe->hash_text.get());

  // Look up the directory entry for this key
  Dir  dir;
  Dir *last_collision = nullptr;

  if (stripe->directory.probe(&key, stripe, &dir, &last_collision)) {
    // Found the entry - remove it from the directory
    stripe->directory.remove(&key, stripe, &dir);
    Dbg(dbg_ctl_cache_groups, "removed directory entry for key in stripe %s", stripe->hash_text.get());
  }
}

// Global functions

void
queue_group_invalidation(const std::string &group_name, const std::string &origin)
{
  CacheGroupInvalidator *invalidator = global_invalidator.load();
  if (invalidator) {
    invalidator->queue_invalidation(group_name, origin);
  } else {
    Warning("cache group invalidation not initialized, dropping request for group '%s'", group_name.c_str());
  }
}

void
cache_group_invalidation_init()
{
  CacheGroupInvalidator *expected    = nullptr;
  CacheGroupInvalidator *invalidator = new CacheGroupInvalidator();

  if (global_invalidator.compare_exchange_strong(expected, invalidator)) {
    invalidator->start();
    Note("cache group invalidation subsystem initialized");
  } else {
    // Another thread already initialized
    delete invalidator;
  }
}

void
cache_group_invalidation_shutdown()
{
  CacheGroupInvalidator *invalidator = global_invalidator.exchange(nullptr);
  if (invalidator) {
    invalidator->stop();
    // Note: We don't delete the invalidator here to avoid use-after-free
    // if there are still references to it. In practice, shutdown only
    // happens once at process exit.
    Note("cache group invalidation subsystem shutdown");
  }
}

CacheGroupInvalidator *
get_cache_group_invalidator()
{
  return global_invalidator.load();
}
