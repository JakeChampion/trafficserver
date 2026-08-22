'''
Verify ip_allow.yaml method filtering accepts QUERY (RFC 10008).
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
Verify ip_allow.yaml method filtering accepts QUERY (RFC 10008).
'''

# QUERY is listed in the ip_allow.yaml methods, so it is proxied.
Test.ATSReplayTest(replay_file="replay/ip_allow_query_allowed.replay.yaml")

# QUERY is absent from the ip_allow.yaml methods, so it is rejected with a 403.
Test.ATSReplayTest(replay_file="replay/ip_allow_query_denied.replay.yaml")
