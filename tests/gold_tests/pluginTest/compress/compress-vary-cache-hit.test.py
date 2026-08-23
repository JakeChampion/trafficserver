'''
Test that Vary: Accept-Encoding is added when a cached object is compressed on
the way out of the cache.
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
Test that Vary: Accept-Encoding is added when a cached object is compressed on
the way out of the cache.
'''

Test.SkipUnless(Condition.PluginExists('compress.so'))
Test.ContinueOnFail = False

# An object cached while its content type was not compressible has no
# Vary: Accept-Encoding.  Once the configuration makes that type compressible,
# the cache hit is compressed, and the response must gain the Vary header --
# without it a downstream cache will hand the compressed body to a client that
# did not ask for it.
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
                   "Cache-Control: max-age=300\r\n"
                   "Content-Type: text/plain\r\n\r\n",
        "timestamp": "1",
        "body": BODY
    })

ts = Test.MakeATSProcess("ts", enable_cache=True)
ts.Disk.records_config.update({
    "proxy.config.diags.debug.enabled": 1,
    "proxy.config.diags.debug.tags": "compress",
})

config_path = ts.Variables.CONFIGDIR + "/compress-vary.config"
ts.Setup.CopyAs("etc/vary-not-compressible.config", ts.Variables.CONFIGDIR, "compress-vary.config")
ts.Disk.plugin_config.AddLine("compress.so {0}".format(config_path))
ts.Disk.remap_config.AddLine("map / http://127.0.0.1:{0}/".format(server.Variables.Port))

# 1. Prime the cache while text/plain is not a compressible type.
tr = Test.AddTestRun("Cache the object while its content type is not compressible")
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.StartBefore(server)
tr.MakeCurlCommand(f'-s -D - -o /dev/null -H "Accept-Encoding: gzip" http://127.0.0.1:{ts.Variables.port}/obj', ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ExcludesExpression(
    "Content-Encoding", "the object is not compressible yet, so it is stored uncompressed")
tr.Processes.Default.Streams.stdout += Testers.ExcludesExpression("Vary", "and stored without a Vary header")
tr.StillRunningAfter = ts

# 2. Make that type compressible and reload.
tr = Test.AddTestRun("Make text/* compressible")
tr.Processes.Default.Command = (
    f"printf 'cache true\\ncompressible-content-type text/*\\nsupported-algorithms gzip\\nminimum-content-length 0\\n' > {config_path}"
)
tr.Processes.Default.ReturnCode = 0
tr.StillRunningAfter = ts

tr = Test.AddConfigReload(ts, description="Reload the compress configuration")
tr.StillRunningAfter = ts

# 3. The cache hit is now compressed, so it must carry Vary: Accept-Encoding.
tr = Test.AddTestRun("A compressed cache hit carries Vary: Accept-Encoding")
tr.MakeCurlCommand(f'-s -D - -o /dev/null -H "Accept-Encoding: gzip" http://127.0.0.1:{ts.Variables.port}/obj', ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "Content-Encoding: gzip", "the cache hit is compressed on the way out")
tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
    "Vary: Accept-Encoding", "a compressed response must tell caches it varies on Accept-Encoding")
tr.StillRunningAfter = ts
