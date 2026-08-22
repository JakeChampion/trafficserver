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
# Check that a response body really is in the format its Content-Encoding
# claims.  Usage: check_gzip_decodes.sh <port> <path> <accept-encoding>

set -u
port=$1
path=$2
accept_encoding=$3

curl -s -D hdr.txt -o body.bin -H "Accept-Encoding: ${accept_encoding}" "http://127.0.0.1:${port}${path}" || exit 1

echo "content-encoding: $(grep -i '^content-encoding' hdr.txt | tr -d '\r' | cut -d' ' -f2-)"

# A gzip stream starts 1f 8b.  A raw deflate stream, which is what the gzip back
# end produces when it is asked for deflate, does not.
echo "body magic: $(od -An -tx1 -N2 body.bin | tr -d ' \n')"

if gzip -d -c body.bin > body.txt 2>/dev/null; then
  echo "gzip decode: ok, $(wc -c < body.txt) bytes"
else
  echo "gzip decode: FAILED"
fi
