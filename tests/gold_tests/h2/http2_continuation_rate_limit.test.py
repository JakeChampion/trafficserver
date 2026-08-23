'''
Test proxy.config.http2.max_continuation_frames_per_minute (CONTINUATION flood mitigation).
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
Verify that an HTTP/2 client flooding CONTINUATION frames faster than
proxy.config.http2.max_continuation_frames_per_minute allows gets its
connection closed with GOAWAY(ENHANCE_YOUR_CALM) (the CONTINUATION flood
mitigation, CVE-2024-27316 class).
'''

Test.SkipUnless(Condition.HasOpenSSLVersion('1.1.1'))

# Tearing the connection down logs an expected HTTP/2 connection error, which
# the default diags.log checks would reject.
ts = Test.MakeATSProcess("ts", enable_tls=True, enable_cache=False, disable_log_checks=True)
ts.addDefaultSSLFiles()
ts.Setup.CopyAs('clients/h2_max_continuation_per_minute.py', Test.RunDirectory)
ts.Disk.records_config.update(
    {
        'proxy.config.ssl.server.cert.path': f'{ts.Variables.SSLDir}',
        'proxy.config.ssl.server.private_key.path': f'{ts.Variables.SSLDir}',
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'http2_con',
        'proxy.config.http2.max_continuation_frames_per_minute': 5,
    })
ts.Disk.ssl_multicert_yaml.AddLines(
    """
ssl_multicert:
  - dest_ip: "*"
    ssl_cert_name: server.pem
    ssl_key_name: server.key
""".split("\n"))
ts.Disk.remap_config.AddLine('map / http://127.0.0.1/')

# Tearing the connection down logs an expected HTTP/2 connection error.
ts.Disk.diags_log.Content = Testers.ContainsExpression(
    'reset too frequent CONTINUATION frames', 'The CONTINUATION frequency limit must trip')

tr = Test.AddTestRun("Flood CONTINUATION frames past the per-minute limit")
tr.Processes.Default.Command = f'{sys.executable} h2_max_continuation_per_minute.py {ts.Variables.ssl_port}'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "Received GOAWAY with error code 11", "Received ENHANCE_YOUR_CALM GOAWAY.")
tr.StillRunningAfter = ts
