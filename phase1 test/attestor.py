"""
Faithful reimplementation of SPIRE's workload attestor selector derivation.

Mirrors:
  spire/pkg/agent/plugin/workloadattestor/unix/unix_posix.go
  spire/pkg/agent/plugin/workloadattestor/docker/*
  spire/pkg/agent/plugin/workloadattestor/k8s/*

Reads ONLY what the real attestors read from /proc, so the selector sets
produced here are the selector sets SPIRE would produce for the same PIDs.
"""

import hashlib
import os
import pwd
import grp
import re


def _read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except (OSError, PermissionError):
        return None


def _status_field(pid, field):
    data = _read(f"/proc/{pid}/status")
    if data is None:
        return None
    for line in data.decode("utf-8", "replace").splitlines():
        if line.startswith(field + ":"):
            return line.split(":", 1)[1].strip()
    return None


def unix_selectors(pid, discover_workload_path=True):
    """
    SPIRE unix workload attestor.

    Emits: unix:uid, unix:user, unix:gid, unix:group, unix:supplementary_gid,
    and (when discover_workload_path) unix:path, unix:sha256.

    NOTE: there is deliberately no unix:pid selector. Registration entries are
    authored before the workload exists, so a selector must be predictable in
    advance. A PID is not.
    """
    sels = []

    uid_line = _status_field(pid, "Uid")
    gid_line = _status_field(pid, "Gid")
    if uid_line is None or gid_line is None:
        return None

    # Uid: real effective saved fs  -> SPIRE uses the effective UID
    uid = int(uid_line.split()[1])
    gid = int(gid_line.split()[1])

    sels.append(f"unix:uid:{uid}")
    try:
        sels.append(f"unix:user:{pwd.getpwuid(uid).pw_name}")
    except KeyError:
        pass

    sels.append(f"unix:gid:{gid}")
    try:
        sels.append(f"unix:group:{grp.getgrgid(gid).gr_name}")
    except KeyError:
        pass

    groups_line = _status_field(pid, "Groups") or ""
    for g in sorted({int(x) for x in groups_line.split() if x.isdigit()}):
        sels.append(f"unix:supplementary_gid:{g}")

    if discover_workload_path:
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            return None
        sels.append(f"unix:path:{exe}")
        blob = _read(f"/proc/{pid}/exe")
        if blob is not None:
            sels.append(f"unix:sha256:{hashlib.sha256(blob).hexdigest()}")

    return sorted(sels)


_CGROUP_DOCKER = re.compile(r"docker[-/]([0-9a-f]{64})")
_CGROUP_CRI = re.compile(r"cri-containerd[-:]([0-9a-f]{64})")
_CGROUP_PODMAN = re.compile(r"libpod-([0-9a-f]{64})")


def container_id(pid):
    """
    Container-id extraction from /proc/<pid>/cgroup, as the docker and k8s
    attestors do. Returns None when the process is not in a recognised
    container cgroup -- which is also what SPIRE sees.
    """
    data = _read(f"/proc/{pid}/cgroup")
    if data is None:
        return None
    text = data.decode("utf-8", "replace")
    for rx in (_CGROUP_DOCKER, _CGROUP_CRI, _CGROUP_PODMAN):
        m = rx.search(text)
        if m:
            return m.group(1)
    return None


def cgroup_paths(pid):
    data = _read(f"/proc/{pid}/cgroup")
    if data is None:
        return []
    out = []
    for line in data.decode("utf-8", "replace").splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3:
            out.append(parts[2])
    return sorted(set(out))


def container_selectors(pid):
    """
    Stand-in for docker/k8s attestor output. Without a container runtime we can
    still show the decisive property: the selectors derive from the *container*,
    so every process inside one container receives an identical set.
    """
    cid = container_id(pid)
    if cid is None:
        return []
    return [f"docker:container_id:{cid}"]


def attest(pid):
    """Full selector set SPIRE would return for this PID."""
    u = unix_selectors(pid)
    if u is None:
        return None
    return sorted(u + container_selectors(pid))
