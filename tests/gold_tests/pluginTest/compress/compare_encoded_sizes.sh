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
# Fetch the same object through two remap rules that differ only in compression
# level, and report whether the cheaper setting produced a bigger body.  Usage:
#   compare_encoded_sizes.sh <port> <label> <accept-encoding> <low-path> <high-path>

set -u
port=$1
label=$2
accept_encoding=$3
low_path=$4
high_path=$5

fetch() {
  curl -s -o "$2" -H "Accept-Encoding: ${accept_encoding}" "http://127.0.0.1:${port}$1" || exit 1
  wc -c < "$2" | tr -d ' '
}

low=$(fetch "${low_path}" low.bin)
high=$(fetch "${high_path}" high.bin)

echo "${label}: low_setting=${low} high_setting=${high}"
if [ "${low}" -gt "${high}" ]; then
  echo "${label}: low_setting_is_larger=yes"
else
  echo "${label}: low_setting_is_larger=no"
fi
