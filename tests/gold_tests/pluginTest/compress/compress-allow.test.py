'''
Test the compress plugin's allow patterns.
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
Test the compress plugin's allow patterns.
'''

Test.SkipUnless(Condition.PluginExists('compress.so'))
Test.ContinueOnFail = False

# allow patterns are matched against the request path, which is the form the
# documentation and sample.compress.config both use.  A pattern that cannot
# match is not merely inert: an allow list with no match disables compression
# for the request entirely.
server = Test.MakeOriginServer("server")

BODY = "the quick brown fox jumps over the lazy dog. " * 40

for path in ["/plain/doc", "/nocompress/doc"]:
    server.addResponse(
        "sessionfile.log", {
            "headers": f"GET {path} HTTP/1.1\r\nHost: *\r\n\r\n",
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

ts.Setup.Copy("etc/allow-paths.config")
ts.Disk.remap_config.AddLine(
    "map / http://127.0.0.1:{0}/ @plugin=compress.so @pparam={1}/allow-paths.config".format(
        server.Variables.Port, Test.RunDirectory))

tr = Test.AddTestRun("A path matching an allow pattern is compressed")
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.StartBefore(server)
tr.MakeCurlCommand(f'-s -D - -o /dev/null -H "Accept-Encoding: gzip" http://127.0.0.1:{ts.Variables.port}/plain/doc', ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "Content-Encoding: gzip", "/plain/doc matches the allow pattern, so it is compressed")
tr.StillRunningAfter = ts

tr = Test.AddTestRun("A path matching a negated allow pattern is not compressed")
tr.MakeCurlCommand(f'-s -D - -o /dev/null -H "Accept-Encoding: gzip" http://127.0.0.1:{ts.Variables.port}/nocompress/doc', ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ExcludesExpression(
    "Content-Encoding", "/nocompress/doc matches the negated pattern, so it is left alone")
tr.StillRunningAfter = ts
