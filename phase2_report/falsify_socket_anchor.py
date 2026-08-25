"""
Phase 2 falsification: attack the "socket is the correct security anchor"
hypothesis that came out of Phase 1 E6.

Phase 1 E6 gave each session its own socket. That was an artifact of the test
harness, not how real agent runtimes talk to LLM APIs and MCP servers. Real
clients pool connections. Test whether the socket survives as a 1:1 anchor for
an agent session under realistic conditions.

F1  connection pooling    -- N sessions through one pooled HTTP client
F2  HTTP/2-style multiplexing -- N logical streams on one socket
F3  socket cookie stability   -- SO_COOKIE across dup(), fork(), threads
F4  SCM_RIGHTS fd passing     -- can a socket be handed to another process?
F5  socket reuse across sessions -- does a pooled socket serve two principals?
"""

import array
import json
import os
import socket
import struct
import sys
import threading
import time
import http.client

SO_COOKIE = 57  # include/uapi/asm-generic/socket.h
RESULTS = "/home/claude/exp2/results_falsification.json"
PORT = 9501


def sock_cookie(s):
    try:
        raw = s.getsockopt(socket.SOL_SOCKET, SO_COOKIE, 8)
        return struct.unpack("Q", raw)[0]
    except OSError as e:
        return f"unavailable: {e}"


def sock_inode(s):
    return os.stat(f"/proc/self/fd/{s.fileno()}").st_ino


# ------------------------------------------------------------------ server
class Server(threading.Thread):
    """Minimal keep-alive HTTP server; records which socket served which
    principal."""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.port = port
        self.stop = threading.Event()
        self.observations = []
        self.lock = threading.Lock()

    def run(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.port))
        srv.listen(64)
        srv.settimeout(0.5)
        while not self.stop.is_set():
            try:
                c, peer = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self.handle, args=(c, peer), daemon=True).start()
        srv.close()

    def handle(self, c, peer):
        c.settimeout(8)
        buf = b""
        try:
            while not self.stop.is_set():
                try:
                    data = c.recv(65536)
                except socket.timeout:
                    break
                if not data:
                    break
                buf += data
                while b"\r\n\r\n" in buf:
                    head, buf = buf.split(b"\r\n\r\n", 1)
                    principal = None
                    for line in head.decode("latin1").split("\r\n"):
                        if line.lower().startswith("x-agent-principal:"):
                            principal = line.split(":", 1)[1].strip()
                    with self.lock:
                        self.observations.append({
                            "server_side_peer_port": peer[1],
                            "claimed_principal": principal,
                        })
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                              b"Connection: keep-alive\r\n\r\nok")
        finally:
            c.close()


# ------------------------------------------------------------------ F1
def f1_connection_pooling(server):
    """
    Four agent sessions, four different delegating humans, sharing ONE pooled
    HTTP client -- the default behaviour of requests.Session, httpx.Client,
    aiohttp, and every LLM SDK built on them.
    """
    print(f"\n{'=' * 74}\n[F1] four sessions through one pooled HTTP client\n{'=' * 74}")
    principals = ["alice@corp", "bob@corp", "carol@corp", "dave@corp"]

    conn = http.client.HTTPConnection("127.0.0.1", PORT)
    conn.connect()
    s = conn.sock
    cookie = sock_cookie(s)
    inode = sock_inode(s)
    lport = s.getsockname()[1]

    for p in principals:
        conn.request("GET", "/v1/messages", headers={"X-Agent-Principal": p})
        conn.getresponse().read()

    time.sleep(0.4)
    obs = [o for o in server.observations if o["server_side_peer_port"] == lport]
    principals_on_socket = sorted({o["claimed_principal"] for o in obs})

    print(f"  sessions                        : {len(principals)}")
    print(f"  distinct principals             : {len(principals)}")
    print(f"  sockets used                    : 1  (lport={lport})")
    print(f"  socket cookie                   : {cookie}")
    print(f"  socket inode                    : {inode}")
    print(f"  principals seen on that ONE sock: {principals_on_socket}")
    print(f"  -> socket:session ratio         : 1:{len(principals_on_socket)}")

    conn.close()
    return {
        "sessions": len(principals),
        "sockets": 1,
        "socket_cookie": cookie,
        "socket_inode": inode,
        "principals_multiplexed_on_one_socket": principals_on_socket,
        "socket_is_1to1_with_session": len(principals_on_socket) <= 1,
    }


# ------------------------------------------------------------------ F2
def f2_stream_multiplexing(server):
    """
    HTTP/2 semantics without an h2 library: N concurrent logical streams
    interleaved on a single TCP socket, each carrying a different principal.
    """
    print(f"\n{'=' * 74}\n[F2] concurrent logical streams on one socket\n{'=' * 74}")
    principals = ["alice@corp", "bob@corp", "carol@corp", "dave@corp"]

    s = socket.create_connection(("127.0.0.1", PORT))
    cookie = sock_cookie(s)
    lport = s.getsockname()[1]
    lock = threading.Lock()

    def stream(pr, sid):
        req = (f"GET /stream/{sid} HTTP/1.1\r\nHost: x\r\n"
               f"X-Agent-Principal: {pr}\r\nConnection: keep-alive\r\n\r\n").encode()
        with lock:
            s.sendall(req)
        time.sleep(0.15)

    ts = [threading.Thread(target=stream, args=(p, i)) for i, p in enumerate(principals)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    time.sleep(0.5)

    obs = [o for o in server.observations if o["server_side_peer_port"] == lport]
    seen = sorted({o["claimed_principal"] for o in obs if o["claimed_principal"]})

    print(f"  concurrent streams              : {len(principals)}")
    print(f"  sockets                         : 1  (cookie={cookie})")
    print(f"  distinct principals on socket   : {len(seen)} -> {seen}")
    print(f"  -> a per-socket verdict cannot separate these streams")

    s.close()
    return {
        "streams": len(principals),
        "sockets": 1,
        "socket_cookie": cookie,
        "principals_on_socket": seen,
        "per_socket_verdict_sufficient": len(seen) <= 1,
    }


# ------------------------------------------------------------------ F3
def f3_cookie_stability():
    """Is the socket cookie stable and unique across dup/fork/threads?"""
    print(f"\n{'=' * 74}\n[F3] socket cookie stability\n{'=' * 74}")
    out = {}

    a = socket.create_connection(("127.0.0.1", PORT))
    b = socket.create_connection(("127.0.0.1", PORT))
    ca, cb = sock_cookie(a), sock_cookie(b)
    out["distinct_sockets_distinct_cookies"] = ca != cb
    print(f"  two sockets -> distinct cookies : {ca != cb}  ({ca} vs {cb})")

    # dup(): same underlying socket, new fd
    dupfd = os.dup(a.fileno())
    dup_sock = socket.socket(fileno=dupfd)
    cdup = sock_cookie(dup_sock)
    out["cookie_survives_dup"] = cdup == ca
    out["dup_produces_new_inode"] = sock_inode(dup_sock) == sock_inode(a)
    print(f"  cookie survives dup()           : {cdup == ca}")
    print(f"  dup shares the same inode       : {sock_inode(dup_sock) == sock_inode(a)}")

    # repeated reads are stable
    out["cookie_stable_over_time"] = all(sock_cookie(a) == ca for _ in range(50))
    print(f"  cookie stable across 50 reads   : {out['cookie_stable_over_time']}")

    # fork(): child inherits the socket
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        os.write(w, str(sock_cookie(a)).encode())
        os._exit(0)
    os.close(w)
    child_cookie = int(os.read(r, 64))
    os.waitpid(pid, 0)
    out["cookie_identical_in_forked_child"] = child_cookie == ca
    print(f"  forked child sees SAME cookie   : {child_cookie == ca}"
          f"  <- two processes, one socket identity")

    dup_sock.detach()
    a.close()
    b.close()
    return out


# ------------------------------------------------------------------ F4
def f4_scm_rights():
    """Hand a live socket to an unrelated process over SCM_RIGHTS."""
    print(f"\n{'=' * 74}\n[F4] socket handover via SCM_RIGHTS\n{'=' * 74}")

    victim = socket.create_connection(("127.0.0.1", PORT))
    cookie_before = sock_cookie(victim)
    owner_pid = os.getpid()

    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    pid = os.fork()
    if pid == 0:
        parent.close()
        msg, anc, flags, addr = child.recvmsg(1, socket.CMSG_SPACE(4))
        fds = array.array("i")
        for level, typ, data in anc:
            if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
                fds.frombytes(data[:len(data) - (len(data) % fds.itemsize)])
        recv_sock = socket.socket(fileno=fds[0])
        c = sock_cookie(recv_sock)
        child.sendall(struct.pack("Q", c if isinstance(c, int) else 0))
        # use the stolen socket
        try:
            recv_sock.sendall(b"GET /stolen HTTP/1.1\r\nHost: x\r\n"
                              b"X-Agent-Principal: ATTACKER\r\n\r\n")
            ok = 1
        except OSError:
            ok = 0
        child.sendall(struct.pack("Q", ok))
        os._exit(0)

    child.close()
    parent.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                            array.array("i", [victim.fileno()]))])
    cookie_in_thief = struct.unpack("Q", parent.recv(8))[0]
    used_ok = struct.unpack("Q", parent.recv(8))[0]
    os.waitpid(pid, 0)

    print(f"  original owner pid              : {owner_pid}")
    print(f"  cookie in original owner        : {cookie_before}")
    print(f"  cookie seen by receiving process: {cookie_in_thief}")
    print(f"  cookie UNCHANGED after handover : {cookie_in_thief == cookie_before}")
    print(f"  receiver could write on socket  : {bool(used_ok)}")
    print(f"  -> socket identity does NOT track the owning process")

    victim.close()
    parent.close()
    return {
        "cookie_before": cookie_before,
        "cookie_in_receiver": cookie_in_thief,
        "cookie_unchanged_after_handover": cookie_in_thief == cookie_before,
        "receiver_could_use_socket": bool(used_ok),
    }


# ------------------------------------------------------------------ F5
def f5_pool_reuse(server):
    """Does a pooled socket get handed from one principal's session to
    another's after the first finishes? (Connection keep-alive reuse.)"""
    print(f"\n{'=' * 74}\n[F5] pooled socket reused across principals\n{'=' * 74}")

    conn = http.client.HTTPConnection("127.0.0.1", PORT)
    conn.connect()
    lport = conn.sock.getsockname()[1]
    cookie = sock_cookie(conn.sock)

    conn.request("GET", "/a", headers={"X-Agent-Principal": "alice@corp"})
    conn.getresponse().read()
    time.sleep(0.2)
    # session A ends; session B picks up the same pooled connection
    conn.request("GET", "/b", headers={"X-Agent-Principal": "bob@corp"})
    conn.getresponse().read()
    time.sleep(0.4)

    obs = [o for o in server.observations if o["server_side_peer_port"] == lport]
    seq = [o["claimed_principal"] for o in obs]
    print(f"  same socket (cookie={cookie})")
    print(f"  principal sequence on it        : {seq}")
    print(f"  socket served >1 principal      : {len(set(seq)) > 1}")

    conn.close()
    return {"socket_cookie": cookie, "principal_sequence": seq,
            "socket_served_multiple_principals": len(set(seq)) > 1}


def main():
    os.makedirs("/home/claude/exp2", exist_ok=True)
    srv = Server(PORT)
    srv.start()
    time.sleep(0.4)

    res = {}
    res["F1_connection_pooling"] = f1_connection_pooling(srv)
    res["F2_stream_multiplexing"] = f2_stream_multiplexing(srv)
    res["F3_cookie_stability"] = f3_cookie_stability()
    res["F4_scm_rights"] = f4_scm_rights()
    res["F5_pool_reuse"] = f5_pool_reuse(srv)

    srv.stop.set()
    time.sleep(0.6)
    with open(RESULTS, "w") as f:
        json.dump(res, f, indent=2, default=str)
    print(f"\nresults -> {RESULTS}")


if __name__ == "__main__":
    main()
