#!/usr/bin/env python3
"""Origin server that drips a compressible chunked body out slowly.

Keeps a transform running long enough for a configuration reload to land in
the middle of it.
"""

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

import argparse
import socket
import sys
import threading
import time

CHUNK = ("the quick brown fox jumps over the lazy dog. " * 20).encode()
CHUNK_COUNT = 8
CHUNK_INTERVAL = 0.5


def handle(conn):
    try:
        conn.settimeout(30)
        data = b''
        while b'\r\n\r\n' not in data:
            more = conn.recv(4096)
            if not more:
                return
            data += more

        conn.sendall(
            b'HTTP/1.1 200 OK\r\n'
            b'Content-Type: text/plain\r\n'
            b'Cache-Control: no-store\r\n'
            b'Transfer-Encoding: chunked\r\n'
            b'Connection: close\r\n\r\n')

        for _ in range(CHUNK_COUNT):
            conn.sendall(b'%x\r\n%s\r\n' % (len(CHUNK), CHUNK))
            time.sleep(CHUNK_INTERVAL)
        conn.sendall(b'0\r\n\r\n')
    except Exception as e:
        print(f"origin: {e}", file=sys.stderr, flush=True)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', args.port))
    sock.listen(16)
    print(f"origin listening on {args.port}", flush=True)

    while True:
        conn, _ = sock.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == '__main__':
    main()
