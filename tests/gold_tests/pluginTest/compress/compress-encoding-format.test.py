'''
Test that a compressed body is in the format its Content-Encoding claims.
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
Test that a compressed body is in the format its Content-Encoding claims.
'''

Test.SkipUnless(Condition.PluginExists('compress.so'), Condition.HasProgram('gzip', 'gzip is required for this test'))
Test.ContinueOnFail = False

# The gzip back end serves both gzip and deflate, and picks between the two wire
# formats -- which differ, gzip having a header and a CRC32 trailer that raw
# deflate does not -- from the encodings the client listed rather than from the
# one that was selected.  A client offering both against a gzip-only
# configuration is the case where those two can disagree, so pin it: whatever
# Content-Encoding says, the body has to be that.
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
ts.Disk.records_config.update(
    {
        "proxy.config.diags.debug.enabled": 1,
        "proxy.config.diags.debug.tags": "compress",
        # Leave Accept-Encoding as the client sent it, so the plugin sees both
        # tokens rather than the single one the core would normalize it to.
        "proxy.config.http.normalize_ae": 0,
    })

ts.Setup.Copy("etc/gzip-only.config")
ts.Disk.remap_config.AddLine(
    "map / http://127.0.0.1:{0}/ @plugin=compress.so @pparam={1}/gzip-only.config".format(server.Variables.Port, Test.RunDirectory))

tr = Test.AddTestRun("A response labelled gzip is a gzip stream")
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.StartBefore(server)
tr.Setup.Copy("check_gzip_decodes.sh")
tr.Processes.Default.Command = f"bash check_gzip_decodes.sh {ts.Variables.port} /obj 'gzip, deflate'"
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "content-encoding: gzip", "gzip is the only enabled algorithm, so it is the one chosen")
tr.Processes.Default.Streams.stdout += Testers.ContainsExpression("body magic: 1f8b", "a gzip stream starts 1f 8b")
tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
    f"gzip decode: ok, {len(BODY)} bytes", "the body decodes as the gzip it claims to be")
tr.StillRunningAfter = ts
