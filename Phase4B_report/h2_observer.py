"""
Phase 4B Test 1: a network observation point sitting on the upstream path.

Forwards bytes between Envoy-front and Envoy-back, and simultaneously tries to
do what an L3/L4 enforcement point would have to do to attribute traffic by
HTTP/2 stream: parse the byte stream and extract stream identifiers.

HTTP/2 frame header (RFC 9113 s4.1), 9 octets:
    length   3 bytes
    type     1 byte
    flags    1 byte
    R+stream 4 bytes  (top bit reserved)

Reports, per upstream connection:
    - whether the HTTP/2 client preface was seen (i.e. is this parseable h2?)
    - how many HEADERS frames were observed, and their stream IDs, with times
    - how many bytes were unparseable

Under TLS the same bytes are opaque, so the preface is absent and no frames
can be extracted. That difference is the measurement.
"""

import json
import os
import socket
import struct
import sys
import threading
import time

LISTEN = int(sys.argv[1]) if len(sys.argv) > 1 else 10003
FORWARD = int(sys.argv[2]) if len(sys.argv) > 2 else 10002
OUT = sys.argv[3] if len(sys.argv) > 3 else "/tmp/observer.json"

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_TYPES = {0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM",
               4: "SETTINGS", 5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY",
               8: "WINDOW_UPDATE", 9: "CONTINUATION"}

obs = {}
lock = threading.Lock()


class ConnParser:
    """Incremental HTTP/2 frame parser for one direction of one connection."""

    def __init__(self, cid):
        self.cid = cid
        self.buf = b""
        self.preface_seen = False
        self.preface_checked = False
        self.frames = []
        self.headers_frames = []
        self.bytes_total = 0
        self.bytes_parsed = 0
        self.parse_failed = False

    def feed(self, data):
        self.bytes_total += len(data)
        self.buf += data

        if not self.preface_checked and len(self.buf) >= len(PREFACE):
            self.preface_checked = True
            if self.buf.startswith(PREFACE):
                self.preface_seen = True
                self.buf = self.buf[len(PREFACE):]
                self.bytes_parsed += len(PREFACE)
            else:
                # Not cleartext h2 -- almost certainly TLS records.
                self.parse_failed = True

        if self.parse_failed or not self.preface_seen:
            return

        while len(self.buf) >= 9:
            ln = int.from_bytes(self.buf[0:3], "big")
            typ = self.buf[3]
            flags = self.buf[4]
            sid = struct.unpack(">I", self.buf[5:9])[0] & 0x7FFFFFFF
            if len(self.buf) < 9 + ln:
                break
            self.buf = self.buf[9 + ln:]
            self.bytes_parsed += 9 + ln
            rec = {"t": time.time(), "type": FRAME_TYPES.get(typ, str(typ)),
                   "stream_id": sid, "len": ln, "flags": flags}
            self.frames.append(rec)
            if typ == 1:
                self.headers_frames.append(rec)


def pump(src, dst, parser=None):
    try:
        while True:
            d = src.recv(65536)
            if not d:
                break
            if parser is not None:
                parser.feed(d)
            dst.sendall(d)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(client, peer, cid):
    up = socket.socket()
    try:
        up.connect(("127.0.0.1", FORWARD))
    except OSError:
        client.close()
        return
    parser = ConnParser(cid)
    with lock:
        obs[cid] = parser
    t1 = threading.Thread(target=pump, args=(client, up, parser), daemon=True)
    t2 = threading.Thread(target=pump, args=(up, client, None), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client.close()
    up.close()


def dump():
    with lock:
        snap = {
            "observed_connections": len(obs),
            "connections": {
                str(c): {
                    "cleartext_h2_preface_seen": p.preface_seen,
                    "parse_failed_opaque_bytes": p.parse_failed,
                    "bytes_total": p.bytes_total,
                    "bytes_parsed": p.bytes_parsed,
                    "parseable_fraction": round(p.bytes_parsed / p.bytes_total, 4)
                                          if p.bytes_total else 0.0,
                    "frames_seen": len(p.frames),
                    "headers_frames": len(p.headers_frames),
                    "distinct_stream_ids": sorted({f["stream_id"]
                                                   for f in p.headers_frames}),
                    "headers_events": [{"t": round(f["t"], 6),
                                        "stream_id": f["stream_id"]}
                                       for f in p.headers_frames],
                } for c, p in obs.items()
            },
        }
    json.dump(snap, open(OUT, "w"), indent=2)


def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LISTEN))
    srv.listen(512)
    srv.settimeout(1.0)
    print(f"observer :{LISTEN} -> :{FORWARD}  out={OUT}", flush=True)
    cid = 0
    last = time.time()
    while True:
        try:
            c, peer = srv.accept()
            cid += 1
            threading.Thread(target=handle, args=(c, peer, cid),
                             daemon=True).start()
        except socket.timeout:
            pass
        if time.time() - last > 1.0:
            dump()
            last = time.time()


if __name__ == "__main__":
    main()
