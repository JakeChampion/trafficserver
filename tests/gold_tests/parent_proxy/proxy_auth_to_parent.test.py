'''
Test proxy.config.http.forward.proxy_auth_to_parent.
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
Verify that the hop-by-hop Proxy-Authorization header is stripped before the
request is sent to a parent proxy by default, and forwarded when
proxy.config.http.forward.proxy_auth_to_parent is enabled.
'''

# Default behavior: Proxy-Authorization is a hop-by-hop header and must not
# be forwarded to the parent.
Test.ATSReplayTest(replay_file="replays/proxy_auth_to_parent_default.replay.yaml")

# With forward.proxy_auth_to_parent enabled the header must reach the parent.
Test.ATSReplayTest(replay_file="replays/proxy_auth_to_parent_enabled.replay.yaml")
