'''
Test the cachekey plugin.
'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

Test.Summary = '''
Verify the cachekey plugin's query parameter handling: --sort-params
normalizes the parameter order in the cache key so requests that differ only
in parameter order share a cache entry, and --remove-all-params drops the
query entirely from the cache key.
'''

Test.SkipUnless(Condition.PluginExists('cachekey.so'), Condition.PluginExists('xdebug.so'))

Test.ATSReplayTest(replay_file="replay/cachekey_sort_params.replay.yaml")

Test.ATSReplayTest(replay_file="replay/cachekey_remove_all_params.replay.yaml")
