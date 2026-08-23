'''
Test that the configured compression levels reach the compressors.
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

import random

Test.Summary = '''
Test that the configured compression levels reach the compressors.
'''

Test.SkipUnless(Condition.PluginExists('compress.so'), Condition.HasATSFeature('TS_HAS_BROTLI'))
# The two cases are independent, so a failure in one should not hide the other.
Test.ContinueOnFail = True

# gzip-compression-level, brotli-compression-level and brotli-lgwin are parsed
# and range checked, so a bad value is rejected at load time and a good one is
# accepted -- but the value was never handed to the compressor, which used a
# fixed level instead.  Nothing in the response says which level produced it, so
# compare two rules that differ only in that setting: a cheaper setting has to
# produce a bigger body.

# Text with enough variety that the level actually changes the result.  A highly
# repetitive body compresses to nearly the same size at every level and would
# make this test pass whatever the plugin did.
random.seed(7)
WORDS = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa", "lambda", "mu"]
BODY = " ".join(random.choice(WORDS) + str(random.randint(0, 999)) for _ in range(1200))

server = Test.MakeOriginServer("server")
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
ts.Disk.records_config.update(
    {
        "proxy.config.diags.debug.enabled": 1,
        "proxy.config.diags.debug.tags": "compress",
        # Leave Accept-Encoding alone.  The default of 1 deletes any
        # Accept-Encoding that is not gzip, which would strip the br the brotli
        # rules need before the plugin ever sees it.
        "proxy.config.http.normalize_ae": 0,
    })

for name in ["gzip-level-1", "gzip-level-9", "brotli-quality-1", "brotli-quality-11"]:
    ts.Setup.Copy(f"etc/{name}.config")
    ts.Disk.remap_config.AddLine(
        f"map /{name}/ http://127.0.0.1:{server.Variables.Port}/ "
        f"@plugin=compress.so @pparam={Test.RunDirectory}/{name}.config")

tr = Test.AddTestRun("gzip honours gzip-compression-level")
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.StartBefore(server)
tr.Setup.Copy("compare_encoded_sizes.sh")
tr.Processes.Default.Command = (f"bash compare_encoded_sizes.sh {ts.Variables.port} gzip gzip /gzip-level-1/obj /gzip-level-9/obj")
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "gzip: low_setting_is_larger=yes", "level 1 must produce a bigger body than level 9")
tr.StillRunningAfter = ts

tr = Test.AddTestRun("brotli honours brotli-compression-level")
tr.Setup.Copy("compare_encoded_sizes.sh")
tr.Processes.Default.Command = (
    f"bash compare_encoded_sizes.sh {ts.Variables.port} brotli br /brotli-quality-1/obj /brotli-quality-11/obj")
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "brotli: low_setting_is_larger=yes", "quality 1 must produce a bigger body than quality 11")
tr.StillRunningAfter = ts
