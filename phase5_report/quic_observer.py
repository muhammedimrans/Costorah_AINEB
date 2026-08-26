"""
Phase 5 RQ3: a network observation point on a QUIC path.

Relays UDP between Envoy-front (HTTP/3 client) and Envoy-back (QUIC server),
parsing what a passive on-path observer could actually extract.

QUIC packet headers (RFC 9000 s17):

  Long header (handshake):  1 1 T T R R P P | version(4) |
                            DCID_len(1) | DCID | SCID_len(1) | SCID | ...
  Short header (1-RTT):     0 1 S R R K P P | DCID | ...

The asymmetry is the finding. Long headers carry explicit connection-ID
lengths, so an observer can parse them. Short headers -- which carry
essentially all application data -- do NOT encode the DCID length on the wire.
Its length is negotiated during the handshake, so an observer that did not
witness (and track) the handshake cannot even determine where the DCID ends.
Everything after the DCID, including all frame types, stream IDs and payload,
is encrypted.
"""

import binascii
import json
import os
import socket
import sys
import threading
import time

LISTEN = int(sys.argv[1]) if len(sys.argv) > 1 else 10013
FORWARD = int(sys.argv[2]) if len(sys.argv) > 2 else 10012
OUT = sys.argv[3] if len(sys.argv) > 3 else "/tmp/quic_obs.json"

state = {
    "datagrams_client_to_server": 0,
    "datagrams_server_to_client": 0,
    "bytes_client_to_server": 0,
    "long_header_packets": 0,
    "short_header_packets": 0,
    "dcids_seen_long_header": {},   # hex -> count
    "scids_seen_long_header": {},
    "versions_seen": {},
    "short_header_dcid_length_on_wire": False,
    "stream_ids_extractable": False,
    "frame_types_extractable": False,
    "five_tuples_client_side": {},  # "ip:port" -> datagrams
    "first_seen": None,
    "last_seen": None,
}
lock = threading.Lock()


def parse(data, direction):
    if not data:
        return
    b0 = data[0]
    is_long = bool(b0 & 0x80)
    with lock:
        if is_long:
            state["long_header_packets"] += 1
            if len(data) < 6:
                return
            ver = binascii.hexlify(data[1:5]).decode()
            state["versions_seen"][ver] = state["versions_seen"].get(ver, 0) + 1
            off = 5
            dl = data[off]
            off += 1
            dcid = binascii.hexlify(data[off:off + dl]).decode()
            off += dl
            if off < len(data):
                sl = data[off]
                off += 1
                scid = binascii.hexlify(data[off:off + sl]).decode()
                state["scids_seen_long_header"][scid] = \
                    state["scids_seen_long_header"].get(scid, 0) + 1
            if dcid:
                state["dcids_seen_long_header"][dcid] = \
                    state["dcids_seen_long_header"].get(dcid, 0) + 1
        else:
            state["short_header_packets"] += 1
            # DCID length is NOT on the wire here. Nothing further is parseable
            # without handshake-derived state and keys.


def relay():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LISTEN))
    srv.settimeout(1.0)

    upstream = {}   # client addr -> socket toward the QUIC server

    def pump_back(usock, caddr):
        usock.settimeout(30)
        while True:
            try:
                d, _ = usock.recvfrom(65535)
            except (socket.timeout, OSError):
                return
            with lock:
                state["datagrams_server_to_client"] += 1
            parse(d, "s2c")
            try:
                srv.sendto(d, caddr)
            except OSError:
                return

    print(f"quic observer udp :{LISTEN} -> :{FORWARD}  out={OUT}", flush=True)
    last = time.time()
    while True:
        try:
            data, caddr = srv.recvfrom(65535)
        except socket.timeout:
            if time.time() - last > 1.0:
                dump()
                last = time.time()
            continue

        with lock:
            now = time.time()
            state["first_seen"] = state["first_seen"] or now
            state["last_seen"] = now
            state["datagrams_client_to_server"] += 1
            state["bytes_client_to_server"] += len(data)
            k = f"{caddr[0]}:{caddr[1]}"
            state["five_tuples_client_side"][k] = \
                state["five_tuples_client_side"].get(k, 0) + 1
        parse(data, "c2s")

        if caddr not in upstream:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream[caddr] = u
            threading.Thread(target=pump_back, args=(u, caddr),
                             daemon=True).start()
        try:
            upstream[caddr].sendto(data, ("127.0.0.1", FORWARD))
        except OSError:
            pass

        if time.time() - last > 1.0:
            dump()
            last = time.time()


def dump():
    with lock:
        s = dict(state)
        s["distinct_client_five_tuples"] = len(s["five_tuples_client_side"])
        s["distinct_dcids_long_header"] = len(s["dcids_seen_long_header"])
        s["distinct_scids_long_header"] = len(s["scids_seen_long_header"])
        total = s["long_header_packets"] + s["short_header_packets"]
        s["total_packets_parsed_headers"] = total
        s["fraction_short_header"] = round(
            s["short_header_packets"] / total, 4) if total else None
        s["parseable_connection_id_fraction"] = round(
            s["long_header_packets"] / total, 4) if total else None
    json.dump(s, open(OUT, "w"), indent=2)


if __name__ == "__main__":
    relay()
