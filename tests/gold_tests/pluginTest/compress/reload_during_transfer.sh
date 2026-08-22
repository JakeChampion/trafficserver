#!/usr/bin/env bash
#
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
#
# Start a slow compressed transfer, then reload the configuration twice while it
# is still running.  Usage: reload_during_transfer.sh <port> <expected-bytes>

set -u
port=$1
expected=$2

curl -s -D hdr.txt -o body.gz -H 'Accept-Encoding: gzip' "http://127.0.0.1:${port}/slow" &
curl_pid=$!

sleep 1
traffic_ctl config reload || echo "reload 1 failed"
sleep 1
traffic_ctl config reload || echo "reload 2 failed"

wait "${curl_pid}"
echo "curl exit: $?"
echo "content-encoding: $(grep -i '^content-encoding' hdr.txt | tr -d '\r' | cut -d' ' -f2-)"
echo "raw bytes: $(wc -c < body.gz)"

if gzip -d -c body.gz > body.txt 2>/dev/null; then
  echo "decoded bytes: $(wc -c < body.txt)"
else
  echo "decoded bytes: gzip -d failed"
fi
echo "expected bytes: ${expected}"
