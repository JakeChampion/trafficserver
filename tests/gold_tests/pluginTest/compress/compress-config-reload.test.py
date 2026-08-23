'''
Test that the compress plugin keeps serving across repeated configuration reloads.
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

import sys

Test.Summary = '''
Test that the compress plugin keeps serving across repeated configuration reloads.
'''

Test.SkipUnless(Condition.PluginExists('compress.so'))
Test.ContinueOnFail = False

# The global configuration is replaced on every traffic_ctl config reload, while
# transactions hold a host configuration that belongs to it.  Reload more than
# once with traffic in between: one reload alone never exercises releasing a
# configuration that has already been replaced.
server = Test.MakeOriginServer("server")

BODY = "the quick brown fox jumps over the lazy dog. " * 40

server.addResponse(
    "sessionfile.log", {
        "headers": "GET /obj HTTP/1.1\r\nHost: *\r\n\r\n",
        "timestamp": "1",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\n"
                   "Connection: close\r\n"
                   "Content-Type: text/plain\r\n\r\n",
        "timestamp": "1",
        "body": BODY
    })

ts = Test.MakeATSProcess("ts", enable_cache=False)
ts.Disk.records_config.update({
    "proxy.config.diags.debug.enabled": 1,
    "proxy.config.diags.debug.tags": "compress",
})

config_path = ts.Variables.CONFIGDIR + "/compress-reload.config"
ts.Setup.CopyAs("etc/reload-base.config", ts.Variables.CONFIGDIR, "compress-reload.config")
ts.Disk.plugin_config.AddLine("compress.so {0}".format(config_path))
ts.Disk.remap_config.AddLine("map /obj http://127.0.0.1:{0}/obj".format(server.Variables.Port))

first = True
for round_number in range(3):
    tr = Test.AddTestRun(f"Compressed response, round {round_number}")
    if first:
        tr.Processes.Default.StartBefore(ts)
        tr.Processes.Default.StartBefore(server)
        first = False
    tr.MakeCurlCommand(f'-s -D - -o /dev/null -H "Accept-Encoding: gzip" http://127.0.0.1:{ts.Variables.port}/obj', ts=ts)
    tr.Processes.Default.ReturnCode = 0
    tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
        "Content-Encoding: gzip", f"still compressing after {round_number} reloads")
    tr.StillRunningAfter = ts

    tr = Test.AddConfigReload(ts, description=f"Reload {round_number}")
    tr.StillRunningAfter = ts

tr = Test.AddTestRun("Compressed response after the last reload")
tr.MakeCurlCommand(f'-s -D - -o /dev/null -H "Accept-Encoding: gzip" http://127.0.0.1:{ts.Variables.port}/obj', ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("Content-Encoding: gzip", "still compressing at the end")
tr.StillRunningAfter = ts

# The reloads above land between transactions.  The case that matters is a
# reload landing *inside* one: the host configuration is dereferenced on every
# body chunk, so a transform still running when its configuration is replaced --
# twice, so the first replacement is released -- is where a stale pointer would
# be used.
Test.GetTcpPort("slow_origin_port")
slow_origin_port = Test.Variables.slow_origin_port
slow_origin = Test.Processes.Process("slow-origin", f"{sys.executable} compress_slow_origin.py --port {slow_origin_port}")
slow_origin.Setup.Copy("compress_slow_origin.py")
slow_origin.Ready = When.PortOpen(slow_origin_port)

ts.Disk.remap_config.AddLine(f"map /slow http://127.0.0.1:{slow_origin_port}/slow")

tr = Test.AddTestRun("Reload twice during a slow compressed transfer")
tr.Processes.Default.StartBefore(slow_origin)
tr.Setup.Copy("reload_during_transfer.sh")
tr.Processes.Default.Env = ts.Env
tr.Processes.Default.Command = f"bash reload_during_transfer.sh {ts.Variables.port} 7200"
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("curl exit: 0", "the transfer must complete")
tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
    f"decoded bytes: 7200", "the whole body must arrive intact through the reloads")
tr.StillRunningAfter = ts
