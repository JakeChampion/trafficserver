'''
Verify correct caching behavior for the HTTP QUERY method (RFC 10008).
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
Verify correct caching behavior for the HTTP QUERY method (RFC 10008).
'''

# Verify a QUERY is forwarded with its content intact and is not cached when
# caching QUERY responses is disabled, which is the default.
Test.ATSReplayTest(replay_file="replay/query_with_query_caching_disabled.replay.yaml")

# Verify QUERY response caching when it is enabled: the request content and its
# Content-Type participate in the cache key, and QUERY and GET responses for the
# same URI do not contaminate each other.
Test.ATSReplayTest(replay_file="replay/query_with_query_caching_enabled.replay.yaml")

# Verify a QUERY whose content exceeds cache.query_max_body_size bypasses the
# cache rather than being keyed on a truncated body.
Test.ATSReplayTest(replay_file="replay/query_with_body_too_large.replay.yaml")
