#!/usr/bin/env python3
"""Measure capture-to-encoded-output latency with the mouse cursor.

Moves the cursor between two points with hyprctl at known times, decodes the
encoder's output as it arrives, and times how long until the cursor shows up
at its new position (and leaves the old one). This covers compositor, capture
and encode -- everything on the laptop. Network and TV add the same on top for
every encoder, so this is the number to compare encoders with.

The cursor moves by itself while this runs; do not touch the mouse.
"""

import argparse
import json
import os
import statistics
import subprocess
import threading
import time

import av
import numpy as np

import probe

ENCODERS = {
    "x264-cbr-zerolatency": dict(encoder="cpu", flags=[], bm=["-bm", "cbr", "-q", "8000"],
                                 opts="flags=-global_header;level=4.2;tune=zerolatency"),
    "vaapi-qp": dict(encoder="gpu", flags=[], bm=["-bm", "qp", "-q", "high"],
                     opts="flags=-global_header;level=4.2;sei=0"),
    "vaapi-qp-async1": dict(encoder="gpu", flags=[], bm=["-bm", "qp", "-q", "high"],
                           opts="flags=-global_header;level=4.2;sei=0;async_depth=1"),
    "vaapi-qp-lowpower": dict(encoder="gpu", flags=["-low-power", "yes"], bm=["-bm", "qp", "-q", "high"],
                              opts="flags=-global_header;level=4.2;sei=0"),
    "vaapi-qp-lowpower-async1": dict(encoder="gpu", flags=["-low-power", "yes"], bm=["-bm", "qp", "-q", "high"],
                                     opts="flags=-global_header;level=4.2;sei=0;async_depth=1"),
}


def cursor_pos():
    x, y = subprocess.run(["hyprctl", "cursorpos"], capture_output=True, text=True).stdout.split(",")
    return int(x), int(y)


def move_cursor(x, y):
    subprocess.run(["hyprctl", "dispatch", f"hl.dsp.cursor.move({{ x = {x}, y = {y} }})"],
                   capture_output=True)


def logical_monitor(name):
    mon = next(m for m in json.loads(subprocess.run(["hyprctl", "monitors", "-j"], capture_output=True,
                                                    text=True).stdout) if m["name"] == name)
    return mon["x"], mon["y"], mon["width"] / mon["scale"], mon["height"] / mon["scale"]


class CaptureReader(threading.Thread):
    """Runs gpu-screen-recorder, splits access units, decodes, keeps (arrival, gray frame)."""

    def __init__(self, cfg, monitor, fps, fit):
        super().__init__(daemon=True)
        self.cmd = ["gpu-screen-recorder", "-w", monitor, "-c", "h264", "-k", "h264", "-f", str(fps),
                    "-fm", "cfr", "-cursor", "yes", "-keyint", "5", "-tune", "performance",
                    "-encoder", cfg["encoder"], *cfg["flags"], *cfg["bm"], "-s", f"{fit[0]}x{fit[1]}",
                    "-ffmpeg-video-opts", cfg["opts"], "-o", "/dev/stdout"]
        self.frames = []
        self.stop = threading.Event()

    def run(self):
        proc = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        fd, decoder = proc.stdout.fileno(), av.CodecContext.create("h264", "r")
        buf, unit, has_vcl = b"", [], False
        try:
            while not self.stop.is_set():
                chunk = os.read(fd, 1 << 16)
                if not chunk:
                    break
                arrived = time.monotonic()
                buf += chunk
                starts, i = [], 0
                while (i := buf.find(b"\x00\x00\x01", i)) >= 0:
                    starts.append(i)
                    i += 3
                if len(starts) < 2:
                    continue
                for a, b in zip(starts, starts[1:]):
                    nal = buf[a + 3:b]
                    if nal.endswith(b"\x00"):
                        nal = nal[:-1]
                    if not nal:
                        continue
                    kind = nal[0] & 0x1F
                    if ((kind in (1, 5) and len(nal) > 1 and nal[1] & 0x80) or kind in (6, 7, 8, 9)) and has_vcl:
                        packet = av.Packet(b"".join(b"\x00\x00\x00\x01" + n for n in unit))
                        for frame in decoder.decode(packet):
                            self.frames.append((arrived, frame.to_ndarray(format="gray")))
                        unit, has_vcl = [], False
                    unit.append(nal)
                    has_vcl = has_vcl or kind in (1, 5)
                buf = buf[starts[-1]:]
        finally:
            proc.send_signal(2)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def patch(gray, px, py, size):
    h, w = gray.shape
    x0, y0 = max(0, px - 4), max(0, py - 4)
    return gray[y0:min(h, py + size), x0:min(w, px + size)].astype(np.int16)


def changed(a, b, threshold=70, min_pixels=15):
    return a.shape == b.shape and int((np.abs(a - b) > threshold).sum()) >= min_pixels


def measure(name, cfg, args):
    mx, my, lw, lh = logical_monitor(args.monitor)
    source = probe.monitor_size(args.monitor)
    scale_fit = min(1.0, args.fit[0] / source[0], args.fit[1] / source[1])
    out_w, out_h = int(source[0] * scale_fit) // 2 * 2, int(source[1] * scale_fit) // 2 * 2
    to_px = out_w / lw
    size = int(36 * to_px)
    points = [(int(lw * 0.22), int(lh * 0.55)), (int(lw * 0.78), int(lh * 0.55))]

    reader = CaptureReader(cfg, args.monitor, args.fps, args.fit)
    reader.start()
    move_cursor(mx + points[0][0], my + points[0][1])
    time.sleep(1.8)
    moves = []
    for i in range(args.moves):
        target, previous = points[(i + 1) % 2], points[i % 2]
        before = time.monotonic()
        move_cursor(mx + target[0], my + target[1])
        moves.append((time.monotonic(), before, target, previous))
        time.sleep(args.dwell)
    time.sleep(0.5)
    reader.stop.set()
    reader.join(timeout=8)

    frames = reader.frames
    latencies, misses = [], 0
    for sent, _, target, previous in moves:
        tpx, tpy = int(target[0] * to_px), int(target[1] * to_px)
        ppx, ppy = int(previous[0] * to_px), int(previous[1] * to_px)
        ref = next((g for t, g in reversed(frames) if t <= sent), None)
        if ref is None:
            misses += 1
            continue
        hit = None
        for t, g in frames:
            if t <= sent:
                continue
            if changed(patch(g, tpx, tpy, size), patch(ref, tpx, tpy, size)) and \
               changed(patch(g, ppx, ppy, size), patch(ref, ppx, ppy, size)):
                hit = t
                break
            if t - sent > 1.5:
                break
        if hit is None:
            misses += 1
        else:
            latencies.append((hit - sent) * 1000)
    arrivals = [t for t, _ in frames]
    fps = (len(arrivals) - 1) / (arrivals[-1] - arrivals[0]) if len(arrivals) > 1 else 0
    return {"encoder": name, "moves": len(moves), "detected": len(latencies), "missed": misses,
            "median_ms": round(statistics.median(latencies)) if latencies else None,
            "min_ms": round(min(latencies)) if latencies else None,
            "p90_ms": round(sorted(latencies)[int(len(latencies) * 0.9)]) if latencies else None,
            "max_ms": round(max(latencies)) if latencies else None,
            "all_ms": [round(v) for v in latencies], "decoded_fps": round(fps, 1)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--monitor", default="eDP-1")
    parser.add_argument("--fps", type=int, default=60)
    parser.add_argument("--fit", default="1920x1080")
    parser.add_argument("--moves", type=int, default=12)
    parser.add_argument("--dwell", type=float, default=0.45)
    parser.add_argument("--encoders", default=",".join(ENCODERS))
    args = parser.parse_args()
    args.fit = tuple(int(v) for v in args.fit.split("x"))
    home = cursor_pos()
    results = []
    try:
        for name in args.encoders.split(","):
            result = measure(name, ENCODERS[name], args)
            results.append(result)
            print(json.dumps({k: v for k, v in result.items() if k != "all_ms"}), flush=True)
    finally:
        move_cursor(*home)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = probe.HERE / "runs" / f"latency-{stamp}.json"
    out.write_text(json.dumps(results, indent=1))
    print(f"saved {out}")


if __name__ == "__main__":
    main()
