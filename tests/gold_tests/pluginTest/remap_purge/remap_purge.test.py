'''
Test the remap_purge plugin.
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

import os

Test.Summary = '''
Verify the remap_purge plugin: an authorized PURGE bumps the cache
generation for the remap rule, instantly invalidating everything previously
cached under it, while an unauthorized PURGE leaves the cache alone.
'''

Test.SkipUnless(Condition.PluginExists('remap_purge.so'), Condition.PluginExists('xdebug.so'))

replay_file = "replay/remap_purge.replay.yaml"

ts = Test.MakeATSProcess("ts")

# The plugin's default state directory does not exist in the test sandbox
# layout, so point the state file at an absolute path in the sandbox. Seed it
# with generation 0 so the plugin does not log an error for a missing file,
# and make it writable by the traffic_server process user.
state_file = os.path.join(ts.Variables.RUNTIMEDIR, 'remap_purge_test.genid')
ts.Setup.CopyAs('remap_purge_test.genid', ts.Variables.RUNTIMEDIR)
ts.chownForATSProcess(state_file)

tr = Test.AddTestRun("Verify remap_purge bumps the cache generation on an authorized PURGE")
server = tr.AddVerifierServerProcess("server", replay_file)
tr.AddVerifierClientProcess("client", replay_file, http_ports=[ts.Variables.port])

ts.Disk.records_config.update({
    'proxy.config.diags.debug.enabled': 1,
    'proxy.config.diags.debug.tags': 'http|remap_purge',
})
ts.Disk.plugin_config.AddLine('xdebug.so --enable=x-cache')
ts.Disk.remap_config.AddLine(
    f'map http://example.com/ http://127.0.0.1:{server.Variables.http_port}/'
    f' @plugin=remap_purge.so @pparam=--state-file={state_file}'
    f' @pparam=--header=ATS-Purger @pparam=--secret=purge-secret-123')

ts.Disk.traffic_out.Content = Testers.ContainsExpression(
    'Bumping the Generation ID to 1', 'The authorized PURGE must bump the generation ID')

tr.Processes.Default.StartBefore(ts)
tr.StillRunningAfter = ts
