'''
Verify how Traffic Server follows a 303 See Other.
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
Verify how Traffic Server follows a 303 See Other.
'''

Test.ContinueOnFail = True

counter = 0


def make_case(name, replay_file, see_other_as_get):
    '''Drive one 303 through Traffic Server and check the followed request.

    The replay file holds two transactions. The client is restricted to the
    first, so the second only ever describes the request Traffic Server makes
    when it follows the redirect, and the method on it is the assertion.
    '''
    global counter
    counter += 1

    ts = Test.MakeATSProcess(f"ts{counter}", enable_cache=False)

    tr = Test.AddTestRun(name)
    # Keyed on the URL: the followed request inherits the original request's
    # headers, so a uuid keyed rule would match it against the wrong transaction.
    server = tr.AddVerifierServerProcess(f"server{counter}", replay_file, other_args='--format "{url}"')

    ts.Disk.records_config.update(
        {
            'proxy.config.diags.debug.enabled': 1,
            'proxy.config.diags.debug.tags': 'http_redirect',
            'proxy.config.http.number_of_redirections': 2,
            # Replaying content across a redirect requires it to have been
            # buffered; without this the replayed request carries a
            # Content-Length with no body behind it.
            'proxy.config.http.request_buffer_enabled': 1,
            'proxy.config.http.redirect.see_other_as_get': see_other_as_get,
            'proxy.config.http.redirect.actions': 'self:follow,loopback:follow,routable:follow',
        })
    ts.Disk.remap_config.AddLine(f'map / http://127.0.0.1:{server.Variables.http_port}/')

    tr.AddVerifierClientProcess(
        f"client{counter}", replay_file, http_ports=[ts.Variables.port], other_args='--format "{url}" --keys "/start"')

    tr.Processes.Default.StartBefore(ts)
    tr.Processes.Default.ReturnCode = 0
    tr.StillRunningAfter = ts


# The default: a 303 is followed with a GET and no content.
make_case("A 303 on a POST is followed with a GET", "replay/see_other_post_to_get.replay.yaml", 1)

# The escape hatch for deployments that depend on the previous behaviour.
make_case("With the setting off, a 303 on a POST keeps the POST", "replay/see_other_post_kept.replay.yaml", 0)

# QUERY is converted whatever the setting says. The setting is off here so that a
# regression making QUERY obey it would fail this case.
make_case("A 303 on a QUERY is followed with a GET even with the setting off", "replay/see_other_query_to_get.replay.yaml", 0)
