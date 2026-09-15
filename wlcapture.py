#!/usr/bin/env python3
"""Direct Wayland screen capture with ext-image-copy-capture-v1.

No portal, no picker, no PipeWire, no gpu-screen-recorder: this talks to the
compositor's capture protocol itself, the way the daemon will. Sources:

  output:NAME      a monitor, including Hyprland virtual outputs (Extend)
  window:TEXT      the first toplevel whose title or app_id contains TEXT (Just an app)

Buffers are shared memory, so there is no GPU format negotiation to fail.
A capture completes only when the image has changed since the last one.

    python wlcapture.py list
    python wlcapture.py bench output:eDP-1 --seconds 5
"""

import argparse
import mmap
import os
import socket
import struct
import threading
import time
import xml.etree.ElementTree as ET

import numpy as np

PROTOCOL_FILES = [
    "/usr/share/wayland/wayland.xml",
    "/usr/share/wayland-protocols/staging/ext-image-capture-source/ext-image-capture-source-v1.xml",
    "/usr/share/wayland-protocols/staging/ext-image-copy-capture/ext-image-copy-capture-v1.xml",
    "/usr/share/wayland-protocols/staging/ext-foreign-toplevel-list/ext-foreign-toplevel-list-v1.xml",
]
SHM_ARGB8888, SHM_XRGB8888 = 0, 1
FAILURE_REASONS = {0: "unknown", 1: "buffer_constraints", 2: "stopped"}


class WaylandError(Exception):
    pass


def load_protocols():
    interfaces = {}
    for path in PROTOCOL_FILES:
        for iface in ET.parse(path).getroot().iter("interface"):
            def messages(kind):
                return [(m.get("name"), [(a.get("type"), a.get("interface")) for a in m.findall("arg")])
                        for m in iface.findall(kind)]
            requests = messages("request")
            interfaces[iface.get("name")] = {
                "requests": requests, "events": messages("event"),
                "opcode": {name: i for i, (name, _) in enumerate(requests)},
            }
    return interfaces


def _string(value):
    raw = value.encode() + b"\x00"
    return struct.pack("<I", len(raw)) + raw + b"\x00" * ((4 - len(raw) % 4) % 4)


class Connection:
    """Minimal Wayland client: XML-driven marshalling, fd passing, per-object handlers."""

    def __init__(self):
        self.protocols = load_protocols()
        path = os.path.join(os.environ["XDG_RUNTIME_DIR"], os.environ.get("WAYLAND_DISPLAY", "wayland-0"))
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.objects, self.handlers = {1: "wl_display"}, {}
        self.next_id, self.buf, self.fds = 2, b"", []
        self.globals = {}
        self.handlers[1] = self._display_event
        self.registry = self.new("wl_registry")
        self.send(1, "get_registry", self.registry)
        self.handlers[self.registry] = self._registry_event
        self.roundtrip()

    def new(self, interface):
        oid, self.next_id = self.next_id, self.next_id + 1
        self.objects[oid] = interface
        return oid

    def on(self, oid, handler):
        self.handlers[oid] = handler

    def send(self, oid, request, *args):
        spec = self.protocols[self.objects[oid]]
        opcode = spec["opcode"][request]
        payload, fds, values = bytearray(), [], iter(args)
        for kind, interface in spec["requests"][opcode][1]:
            if kind == "new_id" and interface is None:  # wl_registry.bind: interface, version, id
                name, version, new = next(values), next(values), next(values)
                payload += _string(name) + struct.pack("<II", version, new)
                continue
            value = next(values)
            if kind in ("int", "fixed"):
                payload += struct.pack("<i", value)
            elif kind in ("uint", "object", "new_id"):
                payload += struct.pack("<I", value or 0)
            elif kind == "string":
                payload += _string(value)
            elif kind == "array":
                payload += struct.pack("<I", len(value)) + value + b"\x00" * ((4 - len(value) % 4) % 4)
            elif kind == "fd":
                fds.append(value)
        header = struct.pack("<II", oid, ((8 + len(payload)) << 16) | opcode)
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack(f"{len(fds)}i", *fds))] if fds else []
        self.sock.sendmsg([header + bytes(payload)], ancillary)

    def dispatch(self, timeout=None):
        self.sock.settimeout(timeout)
        try:
            data, ancillary, _, _ = self.sock.recvmsg(1 << 20, socket.CMSG_SPACE(4 * 28))
        except socket.timeout:
            return False
        if not data:
            raise WaylandError("compositor closed the connection")
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                self.fds += list(struct.unpack(f"{len(payload) // 4}i", payload))
        self.buf += data
        while len(self.buf) >= 8:
            oid, size_opcode = struct.unpack("<II", self.buf[:8])
            size, opcode = size_opcode >> 16, size_opcode & 0xFFFF
            if len(self.buf) < size:
                break
            body, self.buf = self.buf[8:size], self.buf[size:]
            interface = self.objects.get(oid)
            if interface is None:
                continue
            name, arg_types = self.protocols[interface]["events"][opcode]
            args, offset = [], 0
            for kind, target in arg_types:
                if kind in ("int", "fixed"):
                    args.append(struct.unpack_from("<i", body, offset)[0]); offset += 4
                elif kind in ("uint", "object"):
                    args.append(struct.unpack_from("<I", body, offset)[0]); offset += 4
                elif kind == "new_id":
                    nid = struct.unpack_from("<I", body, offset)[0]; offset += 4
                    self.objects[nid] = target
                    args.append(nid)
                elif kind in ("string", "array"):
                    length = struct.unpack_from("<I", body, offset)[0]; offset += 4
                    raw = body[offset:offset + length]; offset += (length + 3) // 4 * 4
                    args.append(raw[:-1].decode(errors="replace") if kind == "string" else raw)
                elif kind == "fd":
                    args.append(self.fds.pop(0))
            handler = self.handlers.get(oid)
            if handler:
                handler(name, args)
        return True

    def roundtrip(self):
        callback, done = self.new("wl_callback"), []
        self.on(callback, lambda name, args: done.append(True))
        self.send(1, "sync", callback)
        while not done:
            self.dispatch()

    def bind(self, interface, version):
        name, available = self.globals[interface][0]
        oid = self.new(interface)
        self.send(self.registry, "bind", name, interface, min(version, available), oid)
        return oid

    def _display_event(self, name, args):
        if name == "error":
            raise WaylandError(f"protocol error on object {args[0]} ({self.objects.get(args[0])}): "
                               f"code {args[1]}: {args[2]}")
        if name == "delete_id":
            self.objects.pop(args[0], None)
            self.handlers.pop(args[0], None)

    def _registry_event(self, name, args):
        if name == "global":
            self.globals.setdefault(args[1], []).append((args[0], args[2]))


def list_outputs(conn):
    outputs = {}
    for global_name, version in conn.globals.get("wl_output", []):
        oid = conn.new("wl_output")
        conn.send(conn.registry, "bind", global_name, "wl_output", min(4, version), oid)
        info = outputs.setdefault(oid, {})
        conn.on(oid, lambda name, args, info=info: info.update(
            {"name": args[0]} if name == "name" else {"mode": (args[1], args[2], args[3] / 1000)} if name == "mode" and args[0] & 1 else {}))
    conn.roundtrip()
    conn.roundtrip()
    return outputs


def list_toplevels(conn):
    toplevels = {}
    listing = conn.bind("ext_foreign_toplevel_list_v1", 1)

    def on_list(name, args):
        if name == "toplevel":
            info = toplevels.setdefault(args[0], {})
            conn.on(args[0], lambda n, a, info=info: info.update({n: a[0]}) if n in ("title", "app_id", "identifier") else None)
    conn.on(listing, on_list)
    conn.roundtrip()
    conn.roundtrip()
    return toplevels


class Capture:
    """One ext-image-copy-capture session writing into a shared-memory buffer."""

    def __init__(self, target, paint_cursors=True):
        self.conn = conn = Connection()
        self.shm = conn.bind("wl_shm", 1)
        manager = conn.bind("ext_image_copy_capture_manager_v1", 1)
        # New object ids must reach the server in increasing order, so every id is
        # allocated immediately before the request that creates it.
        kind, _, wanted = target.partition(":")
        if kind == "output":
            outputs = list_outputs(conn)
            matches = [oid for oid, info in outputs.items() if info.get("name") == wanted]
            if not matches:
                raise WaylandError(f"no output named {wanted!r}; have {[i.get('name') for i in outputs.values()]}")
            source_manager = conn.bind("ext_output_image_capture_source_manager_v1", 1)
            source = conn.new("ext_image_capture_source_v1")
            conn.send(source_manager, "create_source", source, matches[0])
            self.label = f"output {wanted}"
        elif kind == "window":
            toplevels = list_toplevels(conn)
            needle = wanted.lower()
            matches = [(h, i) for h, i in toplevels.items()
                       if needle in i.get("title", "").lower() or needle in i.get("app_id", "").lower()]
            if not matches:
                raise WaylandError(f"no window matching {wanted!r}")
            handle, info = matches[0]
            source_manager = conn.bind("ext_foreign_toplevel_image_capture_source_manager_v1", 1)
            source = conn.new("ext_image_capture_source_v1")
            conn.send(source_manager, "create_source", source, handle)
            self.label = f"window {info.get('app_id')}: {info.get('title', '')[:40]}"
        else:
            raise WaylandError("target must be output:NAME or window:TEXT")

        self.session = conn.new("ext_image_copy_capture_session_v1")
        conn.send(manager, "create_session", self.session, source, 1 if paint_cursors else 0)
        self._pending, self.formats, self.constraints, self.stopped = {}, [], None, False
        self.buffer, self.mm, self.size = None, None, None
        conn.on(self.session, self._session_event)
        while self.constraints is None:
            conn.dispatch()
        self._allocate()

    def _session_event(self, name, args):
        if name == "buffer_size":
            self._pending["size"] = (args[0], args[1])
        elif name == "shm_format":
            self._pending.setdefault("formats", []).append(args[0])
        elif name == "done":
            self.constraints = dict(self._pending)
        elif name == "stopped":
            self.stopped = True

    def _allocate(self):
        conn = self.conn
        width, height = self.constraints["size"]
        formats = self.constraints.get("formats", [])
        fmt = next((f for f in (SHM_XRGB8888, SHM_ARGB8888) if f in formats), None)
        if fmt is None:
            raise WaylandError(f"no 8-bit BGRX/BGRA shm format offered: {formats}")
        if self.buffer:
            conn.send(self.buffer, "destroy")
        nbytes = width * height * 4
        fd = os.memfd_create("airplay-capture")
        os.ftruncate(fd, nbytes)
        self.mm = mmap.mmap(fd, nbytes)
        pool = conn.new("wl_shm_pool")
        conn.send(self.shm, "create_pool", pool, fd, nbytes)
        self.buffer = conn.new("wl_buffer")
        conn.send(pool, "create_buffer", self.buffer, 0, width, height, width * 4, fmt)
        conn.send(pool, "destroy")
        os.close(fd)
        self.size = (width, height)

    def frame(self, timeout=5.0):
        """Block until the source changes; return (ready_monotonic, BGRX array) or None on resize."""
        conn = self.conn
        width, height = self.size
        frame, state = conn.new("ext_image_copy_capture_frame_v1"), {}
        conn.send(self.session, "create_frame", frame)
        conn.on(frame, lambda name, args: state.__setitem__(name, args))
        conn.send(frame, "attach_buffer", self.buffer)
        conn.send(frame, "damage_buffer", 0, 0, width, height)
        conn.send(frame, "capture")
        deadline = time.monotonic() + timeout
        while "ready" not in state and "failed" not in state:
            if not conn.dispatch(max(0.01, deadline - time.monotonic())) and time.monotonic() > deadline:
                conn.send(frame, "destroy")
                return None  # nothing changed within the timeout
        ready_at = time.monotonic()
        conn.send(frame, "destroy")
        if "failed" in state:
            reason = FAILURE_REASONS.get(state["failed"][0], state["failed"][0])
            if reason == "buffer_constraints":
                self.constraints = None
                while self.constraints is None:
                    conn.dispatch()
                self._allocate()
                return None
            raise WaylandError(f"capture failed: {reason}")
        pixels = np.frombuffer(self.mm, dtype=np.uint8).reshape(height, width, 4)
        return ready_at, pixels.copy()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    bench = sub.add_parser("bench")
    bench.add_argument("target")
    bench.add_argument("--seconds", type=float, default=5)
    bench.add_argument("--wiggle", metavar="MONITOR", help="move the cursor on MONITOR to force damage every frame")
    args = parser.parse_args()

    if args.command == "list":
        conn = Connection()
        for info in list_outputs(conn).values():
            mode = info.get("mode")
            print(f"output:{info.get('name')}  {mode[0]}x{mode[1]}@{mode[2]:.0f}" if mode else f"output:{info.get('name')}")
        for info in list_toplevels(conn).values():
            print(f"window  app_id={info.get('app_id')!r:32} title={info.get('title', '')[:60]!r}")
        return

    capture = Capture(args.target)
    print(f"capturing {capture.label} at {capture.size[0]}x{capture.size[1]}")
    stop = threading.Event()
    if args.wiggle:
        import subprocess, json
        def wiggle():
            mons = json.loads(subprocess.run(["hyprctl", "monitors", "-j"], capture_output=True, text=True).stdout)
            m = next(x for x in mons if x["name"] == args.wiggle)
            i = 0
            while not stop.is_set():
                x = m["x"] + 200 + (i % 60) * 6
                subprocess.run(["hyprctl", "dispatch", f"hl.dsp.cursor.move({{ x = {x}, y = {m['y'] + 300} }})"], capture_output=True)
                i += 1
        threading.Thread(target=wiggle, daemon=True).start()
    times, copy_ms = [], []
    started = time.monotonic()
    while time.monotonic() - started < args.seconds:
        t0 = time.monotonic()
        result = capture.frame(timeout=1.0)
        if result:
            times.append(result[0])
            copy_ms.append((time.monotonic() - result[0]) * 1000)
    stop.set()
    if len(times) > 1:
        gaps = sorted((b - a) * 1000 for a, b in zip(times, times[1:]))
        print(f"frames={len(times)} rate={len(times) / (times[-1] - times[0]):.1f}/s "
              f"gap median {gaps[len(gaps) // 2]:.0f} ms p95 {gaps[int(len(gaps) * .95)]:.0f} ms | "
              f"buffer copy {sum(copy_ms) / len(copy_ms):.1f} ms")
    else:
        print(f"frames={len(times)} (nothing changed on screen?)")


if __name__ == "__main__":
    main()
