#!/usr/bin/env python3
"""AirPlay mirroring probe.

Throwaway investigation tool, not the product. It answers four questions
against a real receiver (built for the Samsung Frame):

  1. Which pairing does it accept: transient (no PIN) or PIN pairing?
  2. Does the HAP-encrypted control channel work (encrypted GET /info)?
  3. Does a screen-mirroring control SETUP succeed with NTP or PTP timing,
     and what timing information comes back?
  4. Is a type-110 mirroring stream accepted with the key carried in the
     encrypted SETUP (shk/shiv) and *no* /fp-setup FairPlay exchange at all?

Stage 1 sends no video, so (4) proves the stream is accepted, not that the
receiver can decrypt frames. Stage 2 (--stream-seconds N) answers that: it
encodes a generated test pattern with libx264 and streams it over the
mirroring data channel. If the pattern appears on the TV, the receiver
decrypted frames with no FairPlay involved.

Protocol details were cross-checked against two readable references kept in
ref/: pyatv (MIT) for HAP pairing, and doubletake (LGPL-3.0) for the mirroring
SETUP sequence. This file is an independent implementation.
"""

import argparse
import binascii
import hashlib
import json
import logging
import os
import plistlib
import random
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid
from fractions import Fraction
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from srptools import SRPClientSession, SRPContext, constants

HERE = Path(__file__).resolve().parent
AIRPLAY_PORT = 7000
USER_AGENT = "AirPlay/935.7.1"
SOURCE_VERSION = "980.71.1"
SENDER_NAME = "Omarchy probe"
NTP_EPOCH_OFFSET = 2208988800

# TLV8 types (HAP)
T_METHOD, T_IDENTIFIER, T_SALT, T_PUBLIC_KEY, T_PROOF = 0x00, 0x01, 0x02, 0x03, 0x04
T_ENCRYPTED, T_STATE, T_ERROR, T_RETRY_DELAY, T_SIGNATURE = 0x05, 0x06, 0x07, 0x08, 0x0A
T_NAME, T_ACL, T_FLAGS = 0x11, 0x12, 0x13
HAP_ERRORS = {1: "Unknown", 2: "Authentication (wrong PIN?)", 3: "BackOff", 4: "MaxPeers",
              5: "MaxTries", 6: "Unavailable", 7: "Busy"}

HKP_PIN, HKP_TRANSIENT, HKP_SCREEN_CAPTURE = 3, 4, 5
FLAG_TRANSIENT = 0x10
TRANSIENT_PIN = "3939"
# OPACK {"com.apple.ScreenCapture": true}, requested in M5 for X-Apple-HKP 5.
SCREEN_CAPTURE_ACL = b"\xe1\x57com.apple.ScreenCapture\x01"

log = logging.getLogger("probe")


class ProbeError(Exception):
    pass


# --------------------------------------------------------------------------- helpers

def tlv_encode(items):
    out = bytearray()
    for tag, value in items:
        if not value:
            out += bytes([tag, 0])
        for i in range(0, len(value), 255):
            chunk = value[i:i + 255]
            out += bytes([tag, len(chunk)]) + chunk
    return bytes(out)


def tlv_decode(data):
    result, last = {}, None
    i = 0
    while i + 2 <= len(data):
        tag, length = data[i], data[i + 1]
        value = data[i + 2:i + 2 + length]
        if tag == last and tag in result:
            result[tag] += value
        else:
            result[tag] = value
        last = tag
        i += 2 + length
    return result


def hkdf(secret, salt, info):
    return HKDF(algorithm=hashes.SHA512(), length=32, salt=salt.encode(),
                info=info.encode()).derive(secret)


def nonce_counter(n):
    return b"\x00" * 4 + n.to_bytes(8, "little")


def nonce_label(label):
    return b"\x00" * 4 + label.encode()


def opack_small_string(s):
    raw = s.encode()
    if len(raw) > 0x20:
        raw = raw[:0x20]
    return bytes([0x40 + len(raw)]) + raw


def raw_public(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def boot_ntp_timestamp():
    t = time.clock_gettime(time.CLOCK_BOOTTIME)
    seconds = int(t)
    fraction = int((t - seconds) * (1 << 32)) & 0xFFFFFFFF
    return ((seconds + NTP_EPOCH_OFFSET) << 32) | fraction


def plist_summary(obj, depth=0):
    """Render a plist for the log with byte blobs shortened."""
    if isinstance(obj, bytes):
        return f"<{len(obj)} bytes>"
    if isinstance(obj, dict):
        return {k: plist_summary(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [plist_summary(v, depth + 1) for v in obj]
    return obj


def random_mac():
    octets = [0x02] + [random.randint(0, 255) for _ in range(5)]
    return ":".join(f"{o:02X}" for o in octets)


# --------------------------------------------------------------------------- transport

class HapCipher:
    """HAP framing: 2-byte LE length (AAD) + ChaCha20-Poly1305, 1024-byte frames."""

    def __init__(self, write_key, read_key):
        self._write = ChaCha20Poly1305(write_key)
        self._read = ChaCha20Poly1305(read_key)
        self._write_n = 0
        self._read_n = 0

    def seal(self, data):
        out = bytearray()
        for i in range(0, len(data), 1024):
            frame = data[i:i + 1024]
            aad = len(frame).to_bytes(2, "little")
            out += aad + self._write.encrypt(nonce_counter(self._write_n), frame, aad)
            self._write_n += 1
        return bytes(out)

    def open(self, aad, sealed):
        plain = self._read.decrypt(nonce_counter(self._read_n), sealed, aad)
        self._read_n += 1
        return plain


class RtspConnection:
    def __init__(self, host, port, label="control"):
        self.host, self.port, self.label = host, port, label
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.cseq = 0
        self.cipher = None
        self._buf = b""
        self.lock = threading.Lock()

    @property
    def local_ip(self):
        return self.sock.getsockname()[0]

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def _recv_exact(self, n):
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ProbeError(f"{self.label}: connection closed by receiver")
            data += chunk
        return data

    def _fill(self):
        if self.cipher is None:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ProbeError(f"{self.label}: connection closed by receiver")
            self._buf += chunk
        else:
            aad = self._recv_exact(2)
            size = int.from_bytes(aad, "little")
            self._buf += self.cipher.open(aad, self._recv_exact(size + 16))

    def read_message(self):
        while b"\r\n\r\n" not in self._buf:
            self._fill()
        head, _, rest = self._buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        length = int(headers.get("content-length", "0"))
        while len(rest) < length:
            self._fill()
            _, _, rest = self._buf.partition(b"\r\n\r\n")
        body, self._buf = rest[:length], rest[length:]
        return lines[0], headers, body

    def request(self, method, uri, headers=None, body=b"", content_type=None, timeout=15, quiet=False):
        with self.lock:
            return self._request(method, uri, headers, body, content_type, timeout, quiet)

    def _request(self, method, uri, headers, body, content_type, timeout, quiet):
        self.cseq += 1
        lines = [f"{method} {uri} RTSP/1.0", f"CSeq: {self.cseq}", f"User-Agent: {USER_AGENT}"]
        for k, v in (headers or {}).items():
            lines.append(f"{k}: {v}")
        if content_type and body:
            lines.append(f"Content-Type: {content_type}")
        lines.append(f"Content-Length: {len(body)}")
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
        self.sock.settimeout(timeout)
        started = time.monotonic()
        self.sock.sendall(self.cipher.seal(raw) if self.cipher else raw)
        try:
            status_line, rheaders, rbody = self.read_message()
        except socket.timeout:
            raise ProbeError(f"{method} {uri}: no response after {timeout}s") from None
        elapsed = (time.monotonic() - started) * 1000
        parts = status_line.split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        if not quiet:
            log.info("  %s %s -> %s (%d bytes, %.0f ms%s)", method, uri, status_line.split(" ", 1)[-1],
                     len(rbody), elapsed, ", encrypted" if self.cipher else "")
        return status, rheaders, rbody


def decode_plist(body):
    if not body:
        return {}
    try:
        return plistlib.loads(body)
    except Exception:
        return {"_undecodable": body[:64].hex()}


# --------------------------------------------------------------------------- pairing

def srp_exchange(conn, headers, m1_items, pin_supplier, report):
    status, _, body = conn.request("POST", "/pair-setup", headers, tlv_encode(m1_items),
                                   "application/octet-stream")
    if status != 200:
        raise ProbeError(f"pair-setup M1 rejected with HTTP {status}")
    m2 = tlv_decode(body)
    if T_ERROR in m2:
        code = m2[T_ERROR][0]
        raise ProbeError(f"pair-setup M2 error {code}: {HAP_ERRORS.get(code, '?')}")
    salt, server_public = m2[T_SALT], m2[T_PUBLIC_KEY]
    report["m2"] = {"salt_bytes": len(salt), "public_key_bytes": len(server_public)}

    pin = pin_supplier()
    context = SRPContext("Pair-Setup", pin, prime=constants.PRIME_3072,
                         generator=constants.PRIME_3072_GEN, hash_func=hashlib.sha512)
    session = SRPClientSession(context, binascii.hexlify(os.urandom(32)).decode())
    session.process(binascii.hexlify(server_public).decode(), binascii.hexlify(salt).decode())
    client_public = binascii.unhexlify(session.public)
    client_proof = binascii.unhexlify(session.key_proof)

    status, _, body = conn.request(
        "POST", "/pair-setup", headers,
        tlv_encode([(T_STATE, b"\x03"), (T_PUBLIC_KEY, client_public), (T_PROOF, client_proof)]),
        "application/octet-stream")
    if status != 200:
        raise ProbeError(f"pair-setup M3 rejected with HTTP {status}")
    m4 = tlv_decode(body)
    if T_ERROR in m4:
        code = m4[T_ERROR][0]
        raise ProbeError(f"pair-setup M4 error {code}: {HAP_ERRORS.get(code, '?')}")
    if T_PROOF not in m4 or not session.verify_proof(binascii.hexlify(m4[T_PROOF])):
        raise ProbeError("receiver's SRP proof did not verify")
    return binascii.unhexlify(session.key)


def pair_transient(conn, report):
    headers = {"X-Apple-HKP": str(HKP_TRANSIENT)}
    status, _, _ = conn.request("POST", "/pair-pin-start", headers)
    report["pair_pin_start_status"] = status
    shared = srp_exchange(
        conn, headers,
        [(T_METHOD, b"\x00"), (T_STATE, b"\x01"), (T_FLAGS, bytes([FLAG_TRANSIENT]))],
        lambda: TRANSIENT_PIN, report)
    return shared


def wait_for_pin(pin_file, timeout):
    pin_file.unlink(missing_ok=True)
    log.info("")
    log.info("  >>> A PIN should now be on the TV. Write it to the pin file:")
    log.info("  >>>   echo 1234 > %s", pin_file)
    log.info("")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pin_file.exists():
            pin = re.sub(r"\D", "", pin_file.read_text())
            pin_file.unlink(missing_ok=True)
            if pin:
                log.info("  PIN received (%d digits)", len(pin))
                return pin
        time.sleep(0.5)
    raise ProbeError(f"no PIN written to {pin_file} within {timeout}s")


def pair_setup_pin(conn, hkp, pin_file, pin_timeout, report):
    headers = {"X-Apple-HKP": str(hkp)}
    status, _, _ = conn.request("POST", "/pair-pin-start", headers)
    report["pair_pin_start_status"] = status
    k = srp_exchange(conn, headers, [(T_METHOD, b"\x00"), (T_STATE, b"\x01")],
                     lambda: wait_for_pin(pin_file, pin_timeout), report)

    ltsk = Ed25519PrivateKey.generate()
    ltpk = raw_public(ltsk)
    pairing_id = str(uuid.uuid4()).upper().encode()
    controller_x = hkdf(k, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info")
    sub = [(T_IDENTIFIER, pairing_id), (T_PUBLIC_KEY, ltpk),
           (T_SIGNATURE, ltsk.sign(controller_x + pairing_id + ltpk)),
           (T_NAME, b"\xe1\x44name" + opack_small_string(SENDER_NAME))]
    if hkp == HKP_SCREEN_CAPTURE:
        sub.append((T_ACL, SCREEN_CAPTURE_ACL))
    setup_key = hkdf(k, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info")
    sealed = ChaCha20Poly1305(setup_key).encrypt(nonce_label("PS-Msg05"), tlv_encode(sub), None)
    status, _, body = conn.request("POST", "/pair-setup", headers,
                                   tlv_encode([(T_STATE, b"\x05"), (T_ENCRYPTED, sealed)]),
                                   "application/octet-stream")
    m6 = tlv_decode(body)
    if status != 200 or T_ERROR in m6:
        code = m6.get(T_ERROR, b"\x00")[0]
        raise ProbeError(f"pair-setup M6 failed (HTTP {status}, error {code}: {HAP_ERRORS.get(code, '?')})")
    accessory = tlv_decode(ChaCha20Poly1305(setup_key).decrypt(nonce_label("PS-Msg06"), m6[T_ENCRYPTED], None))
    tv_id, tv_ltpk, tv_sig = accessory[T_IDENTIFIER], accessory[T_PUBLIC_KEY], accessory[T_SIGNATURE]
    accessory_x = hkdf(k, "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info")
    try:
        Ed25519PublicKey.from_public_bytes(tv_ltpk).verify(tv_sig, accessory_x + tv_id + tv_ltpk)
        report["m6_signature"] = "valid"
    except InvalidSignature:
        report["m6_signature"] = "INVALID"
    return {"hkp": hkp, "pairing_id": pairing_id.decode(),
            "ltsk": ltsk.private_bytes_raw().hex(), "tv_id": tv_id.decode(errors="replace"),
            "tv_ltpk": tv_ltpk.hex()}


def pair_verify(conn, creds, report):
    headers = {"X-Apple-HKP": str(creds["hkp"])}
    eph = X25519PrivateKey.generate()
    eph_pub = raw_public(eph)
    status, _, body = conn.request("POST", "/pair-verify", headers,
                                   tlv_encode([(T_STATE, b"\x01"), (T_PUBLIC_KEY, eph_pub)]),
                                   "application/octet-stream")
    m2 = tlv_decode(body)
    if status != 200 or T_ERROR in m2:
        code = m2.get(T_ERROR, b"\x00")[0]
        raise ProbeError(f"pair-verify M2 failed (HTTP {status}, error {code}: {HAP_ERRORS.get(code, '?')})")
    tv_eph = m2[T_PUBLIC_KEY]
    shared = eph.exchange(X25519PublicKey.from_public_bytes(tv_eph))
    verify_key = hkdf(shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")
    inner = tlv_decode(ChaCha20Poly1305(verify_key).decrypt(nonce_label("PV-Msg02"), m2[T_ENCRYPTED], None))
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(creds["tv_ltpk"])).verify(
            inner[T_SIGNATURE], tv_eph + inner[T_IDENTIFIER] + eph_pub)
        report["pv_signature"] = "valid"
    except InvalidSignature:
        raise ProbeError("pair-verify: receiver signature invalid (stale credentials?)") from None
    ltsk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(creds["ltsk"]))
    pairing_id = creds["pairing_id"].encode()
    sealed = ChaCha20Poly1305(verify_key).encrypt(
        nonce_label("PV-Msg03"),
        tlv_encode([(T_IDENTIFIER, pairing_id), (T_SIGNATURE, ltsk.sign(eph_pub + pairing_id + tv_eph))]),
        None)
    status, _, body = conn.request("POST", "/pair-verify", headers,
                                   tlv_encode([(T_STATE, b"\x03"), (T_ENCRYPTED, sealed)]),
                                   "application/octet-stream")
    m4 = tlv_decode(body)
    if status != 200 or T_ERROR in m4:
        code = m4.get(T_ERROR, b"\x00")[0]
        raise ProbeError(f"pair-verify M4 failed (HTTP {status}, error {code}: {HAP_ERRORS.get(code, '?')})")
    return shared


# --------------------------------------------------------------------------- side channels

class TimingResponder(threading.Thread):
    """Answers AirPlay NTP timing requests (0xd2 -> 0xd3) and counts traffic."""

    def __init__(self, sock):
        super().__init__(daemon=True)
        self.sock = sock
        self.stop = threading.Event()
        self.requests = 0
        self.other = 0
        self.sources = set()

    def run(self):
        self.sock.settimeout(0.5)
        while not self.stop.is_set():
            try:
                data, addr = self.sock.recvfrom(256)
            except socket.timeout:
                continue
            except OSError:
                return
            self.sources.add(addr[0])
            if len(data) >= 32 and data[0] == 0x80 and data[1] == 0xD2:
                self.requests += 1
                reply = bytearray(data[:32])
                reply[1] = 0xD3
                now = boot_ntp_timestamp()
                reply[8:16] = data[24:32]
                reply[16:24] = now.to_bytes(8, "big")
                reply[24:32] = now.to_bytes(8, "big")
                try:
                    self.sock.sendto(bytes(reply), addr)
                except OSError:
                    pass
            else:
                self.other += 1

    def probe_receiver(self, host, port):
        for seq in range(1, 4):
            packet = bytearray(32)
            packet[0], packet[1] = 0x80, 0xD2
            packet[2:4] = seq.to_bytes(2, "big")
            packet[24:32] = boot_ntp_timestamp().to_bytes(8, "big")
            self.sock.sendto(bytes(packet), (host, port))
            time.sleep(0.1)


class EventChannel(threading.Thread):
    """Sender side of the receiver's event connection. Logs and 200s every request."""

    def __init__(self, host, port, shared):
        super().__init__(daemon=True)
        self.conn = RtspConnection(host, port, label="event")
        # Direction is reversed relative to the control channel.
        self.conn.cipher = HapCipher(
            write_key=hkdf(shared, "Events-Salt", "Events-Read-Encryption-Key"),
            read_key=hkdf(shared, "Events-Salt", "Events-Write-Encryption-Key"))
        self.received = []

    def run(self):
        self.conn.sock.settimeout(None)
        try:
            while True:
                request_line, headers, body = self.conn.read_message()
                summary = plist_summary(decode_plist(body)) if body else None
                self.received.append({"request": request_line, "body": summary})
                log.info("  [event] %s %s", request_line, json.dumps(summary, default=str)[:300] if summary else "")
                reply = (f"RTSP/1.0 200 OK\r\nCSeq: {headers.get('cseq', '0')}\r\n"
                         f"Content-Length: 0\r\n\r\n").encode()
                self.conn.sock.sendall(self.conn.cipher.seal(reply))
        except (ProbeError, OSError, ValueError) as exc:
            log.info("  [event] channel ended: %s", exc)


# --------------------------------------------------------------------------- stage 2: video

MIRROR_HEADER = 128


def ntp_now_with_lead(lead_seconds):
    t = time.clock_gettime(time.CLOCK_BOOTTIME) + lead_seconds
    seconds = int(t)
    return ((seconds + NTP_EPOCH_OFFSET) << 32) | (int((t - seconds) * (1 << 32)) & 0xFFFFFFFF)


def split_annexb(data):
    """Split an Annex B byte stream into NAL units (start codes removed)."""
    starts, i = [], 0
    while True:
        i = data.find(b"\x00\x00\x01", i)
        if i < 0:
            break
        starts.append(i + 3)
        i += 3
    nals = []
    for index, start in enumerate(starts):
        end = starts[index + 1] - 3 if index + 1 < len(starts) else len(data)
        nal = data[start:end]
        if index + 1 < len(starts) and nal.endswith(b"\x00"):
            nal = nal[:-1]  # 4-byte start code of the next NAL
        if nal:
            nals.append(nal)
    return nals


def build_avcc(sps, pps):
    record = (bytes([1, sps[1], sps[2], sps[3], 0xFF, 0xE1]) + len(sps).to_bytes(2, "big") + sps
              + b"\x01" + len(pps).to_bytes(2, "big") + pps)
    return record + b"\x02\x00\x00\x00"  # trailer observed from Apple senders


class TestPattern:
    def __init__(self, width, height):
        from PIL import Image, ImageDraw, ImageFont
        self.Image, self.ImageDraw = Image, ImageDraw
        self.w, self.h = width, height
        self.split = int(height * 0.62)
        base = Image.new("RGB", (width, height), (18, 16, 26))
        draw = ImageDraw.Draw(base)
        bars = [(192, 192, 192), (192, 192, 0), (0, 192, 192), (0, 192, 0),
                (192, 0, 192), (192, 0, 0), (0, 0, 192)]
        bar_w = width // len(bars)
        for i, colour in enumerate(bars):
            draw.rectangle([i * bar_w, 0, (i + 1) * bar_w if i < len(bars) - 1 else width, self.split], fill=colour)
        self.font_big = ImageFont.load_default(size=int(height * 0.075))
        self.font_small = ImageFont.load_default(size=int(height * 0.04))
        draw.text((int(width * 0.05), int(height * 0.66)), "Omarchy -> AirPlay", font=self.font_big, fill=(255, 255, 255))
        draw.text((int(width * 0.05), int(height * 0.765)), "stage 2 probe  |  no FairPlay",
                  font=self.font_small, fill=(169, 155, 245))
        self.base = base

    def frame(self, n, fps):
        img = self.base.copy()
        draw = self.ImageDraw.Draw(img)
        period = fps * 4
        x = int((n % period) / period * self.w)
        draw.rectangle([max(0, x - 24), 0, min(self.w, x + 24), self.split], fill=(255, 255, 255))
        draw.text((int(self.w * 0.05), int(self.h * 0.86)),
                  f"frame {n:05d}     {time.strftime('%H:%M:%S')}", font=self.font_small, fill=(235, 235, 235))
        return img


class MirrorStreamer:
    """Encodes the test pattern and writes AirPlay screen packets to the data socket."""

    def __init__(self, sock, mode, shared, stream_id, shk, shiv, width, height, fps, bitrate, lead):
        import av
        self.av = av
        self.sock, self.mode = sock, mode
        self.width, self.height, self.fps, self.lead = width, height, fps, lead
        self.stats = {"cipher": mode, "codec_packets": 0, "video_frames": 0, "idr_frames": 0,
                      "bytes_sent": 0, "heartbeats": 0, "encode_ms_avg": None, "bytes_from_receiver": 0,
                      "receiver_closed": False}
        if mode == "chacha":
            key = HKDF(algorithm=hashes.SHA512(), length=32,
                       salt=f"DataStream-Salt{stream_id}".encode(),
                       info=b"DataStream-Output-Encryption-Key").derive(shared)
            self.chacha, self.nonce = ChaCha20Poly1305(key), 0
        elif mode == "aesctr":
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            key = hashlib.sha512(f"AirPlayStreamKey{stream_id}".encode() + shk).digest()[:16]
            iv = hashlib.sha512(f"AirPlayStreamIV{stream_id}".encode() + shk).digest()[:16]
            self.ctr = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        self.last_ts = 0

        self.encoder = av.CodecContext.create("libx264", "w")
        self.encoder.width, self.encoder.height = width, height
        self.encoder.pix_fmt = "yuv420p"
        self.encoder.time_base = Fraction(1, fps)
        self.encoder.framerate = Fraction(fps, 1)
        self.encoder.bit_rate = bitrate
        self.encoder.options = {
            "preset": "ultrafast", "tune": "zerolatency", "profile": "high", "level": "4.2",
            "x264-params": f"keyint={fps}:min-keyint={fps}:bframes=0:repeat-headers=1:annexb=1",
        }

    def _timestamp(self):
        ts = max(ntp_now_with_lead(self.lead), self.last_ts + 1)
        self.last_ts = ts
        return ts

    def _write(self, data):
        self.sock.sendall(data)
        self.stats["bytes_sent"] += len(data)

    def send_codec(self, sps, pps):
        payload = build_avcc(sps, pps)
        header = bytearray(MIRROR_HEADER)
        header[0:4] = len(payload).to_bytes(4, "little")
        header[4], header[5], header[6], header[7] = 0x01, 0x00, 0x16, 0x01
        header[8:16] = self._timestamp().to_bytes(8, "little")
        for offset in (16, 40, 56):
            header[offset:offset + 4] = struct.pack("<f", float(self.width))
            header[offset + 4:offset + 8] = struct.pack("<f", float(self.height))
        self._write(bytes(header) + payload)
        self.stats["codec_packets"] += 1

    def send_frame(self, payload, idr):
        header = bytearray(MIRROR_HEADER)
        size = len(payload) + (16 if self.mode == "chacha" else 0)
        header[0:4] = size.to_bytes(4, "little")
        header[4], header[5] = 0x00, (0x10 if idr else 0x00)
        header[8:16] = self._timestamp().to_bytes(8, "little")
        if self.mode == "chacha":
            body = self.chacha.encrypt(nonce_counter(self.nonce), payload, bytes(header))
            self.nonce += 1
        elif self.mode == "aesctr":
            body = self.ctr.update(payload)
        else:
            body = payload
        self._write(bytes(header) + body)
        self.stats["video_frames"] += 1
        self.stats["idr_frames"] += int(idr)

    def send_heartbeat(self):
        header = bytearray(MIRROR_HEADER)
        header[4], header[6] = 0x02, 0x1E
        self._write(bytes(header))
        self.stats["heartbeats"] += 1

    def _drain_receiver(self):
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if not chunk:
                self.stats["receiver_closed"] = True
                return
            self.stats["bytes_from_receiver"] += len(chunk)

    def run(self, seconds):
        pattern = TestPattern(self.width, self.height)
        self._stop = threading.Event()
        reader = threading.Thread(target=self._drain_receiver, daemon=True)
        reader.start()
        sent_params, encode_ms = None, []
        started = time.monotonic()
        next_heartbeat = None
        n = 0
        try:
            while time.monotonic() - started < seconds and not self.stats["receiver_closed"]:
                due = started + n / self.fps
                delay = due - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                t0 = time.monotonic()
                frame = self.av.VideoFrame.from_image(pattern.frame(n, self.fps)).reformat(format="yuv420p")
                frame.pts = n
                packets = self.encoder.encode(frame)
                encode_ms.append((time.monotonic() - t0) * 1000)
                for packet in packets:
                    nals = split_annexb(bytes(packet))
                    sps = next((x for x in nals if x[0] & 0x1F == 7), None)
                    pps = next((x for x in nals if x[0] & 0x1F == 8), None)
                    if sps and pps and (sps, pps) != sent_params:
                        self.send_codec(sps, pps)
                        sent_params = (sps, pps)
                    vcl = [x for x in nals if x[0] & 0x1F in (1, 5)]
                    if vcl and sent_params:
                        idr = any(x[0] & 0x1F == 5 for x in vcl)
                        self.send_frame(b"".join(len(x).to_bytes(4, "big") + x for x in vcl), idr)
                        if next_heartbeat is None:
                            next_heartbeat = time.monotonic() + 1
                if next_heartbeat and time.monotonic() >= next_heartbeat:
                    self.send_heartbeat()
                    next_heartbeat += 1
                if n % self.fps == 0:
                    log.info("    t=%4.1fs frames=%d idr=%d sent=%.1f MB encode=%.0f ms/frame",
                             time.monotonic() - started, self.stats["video_frames"], self.stats["idr_frames"],
                             self.stats["bytes_sent"] / 1e6, sum(encode_ms[-self.fps:]) / len(encode_ms[-self.fps:]))
                n += 1
        except OSError as exc:
            self.stats["write_error"] = str(exc)
            log.info("    data channel write failed: %s", exc)
        finally:
            self._stop.set()
        elapsed = time.monotonic() - started
        self.stats["seconds"] = round(elapsed, 2)
        self.stats["effective_fps"] = round(self.stats["video_frames"] / elapsed, 1) if elapsed else 0
        self.stats["encode_ms_avg"] = round(sum(encode_ms) / len(encode_ms), 1) if encode_ms else None
        return self.stats


class FeedbackLoop(threading.Thread):
    """POST /feedback every 2 s on the control connection, starting immediately."""

    def __init__(self, conn):
        super().__init__(daemon=True)
        self.conn, self.stop, self.results = conn, threading.Event(), []

    def run(self):
        while not self.stop.is_set():
            try:
                status, _, _ = self.conn.request("POST", "/feedback", {}, timeout=5, quiet=True)
                self.results.append(status)
            except (ProbeError, OSError) as exc:
                self.results.append(f"error: {exc}")
                return
            self.stop.wait(2)


# --------------------------------------------------------------------------- discovery

def discover(name_pattern):
    try:
        out = subprocess.run(["avahi-browse", "-rpt", "_airplay._tcp"], capture_output=True,
                             text=True, timeout=15).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    for line in out.splitlines():
        fields = line.split(";")
        if len(fields) < 10 or fields[0] != "=" or fields[2] != "IPv4":
            continue
        name = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), fields[3])
        if re.search(name_pattern, name, re.I):
            txt = dict(re.findall(r'"([^"=]+)=([^"]*)"', fields[9]))
            return {"name": name, "host": fields[7], "port": int(fields[8]), "txt": txt}
    return None


# --------------------------------------------------------------------------- probe

def run(args):
    started = time.strftime("%Y%m%d-%H%M%S")
    run_dir = HERE / "runs" / f"{started}-{args.timing}-{args.pairing}"
    run_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(run_dir / "log.txt")
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    log.addHandler(handler)

    report = {"started": started, "args": vars(args), "steps": {}}
    steps = report["steps"]
    host = args.host
    if not host:
        found = discover(args.name)
        if not found:
            raise ProbeError(f"no AirPlay receiver matching /{args.name}/ found via mDNS")
        host = found["host"]
        report["receiver"] = found
        log.info("Receiver: %s at %s (sourceVersion %s)", found["name"], host, found["txt"].get("srcvers"))

    conn = event = timing = None
    timing_sock = None
    session_uuid = str(uuid.uuid4()).upper()
    audio_sc_id = random.getrandbits(63)
    audio_uri = f"rtsp://{host}:{AIRPLAY_PORT}/{audio_sc_id}"
    try:
        # 1. Pairing -------------------------------------------------------
        log.info("[1] Pairing (%s)", args.pairing)
        creds_path = HERE / "credentials.json"
        attempts = []
        if args.pairing in ("auto", "transient"):
            attempts.append("transient")
        if args.pairing in ("auto", "pin"):
            attempts.append("pin")
        shared = None
        for method in attempts:
            conn = RtspConnection(host, AIRPLAY_PORT)
            step = steps.setdefault(f"pairing_{method}", {})
            try:
                if method == "transient":
                    shared = pair_transient(conn, step)
                else:
                    stored = json.loads(creds_path.read_text()) if creds_path.exists() else {}
                    creds = stored.get(host)
                    if creds and not args.repair:
                        step["used_stored_credentials"] = True
                    else:
                        creds = pair_setup_pin(conn, args.hkp, args.pin_file, args.pin_timeout, step)
                        stored[host] = creds
                        creds_path.write_text(json.dumps(stored, indent=1))
                        creds_path.chmod(0o600)
                        conn.close()
                        conn = RtspConnection(host, AIRPLAY_PORT)
                    shared = pair_verify(conn, creds, step)
                step["result"] = "ok"
                report["pairing"] = method
                log.info("    pairing OK via %s", method)
                break
            except ProbeError as exc:
                step["result"] = f"failed: {exc}"
                log.info("    %s pairing failed: %s", method, exc)
                conn.close()
                conn = None
        if shared is None:
            raise ProbeError("no pairing method succeeded")

        write_key = hkdf(shared, "Control-Salt", "Control-Write-Encryption-Key")
        read_key = hkdf(shared, "Control-Salt", "Control-Read-Encryption-Key")
        conn.cipher = HapCipher(write_key, read_key)

        # 2. Encrypted channel --------------------------------------------
        log.info("[2] Encrypted GET /info")
        status, _, body = conn.request("GET", "/info", {}, timeout=10)
        info = decode_plist(body)
        steps["encrypted_info"] = {"status": status, "keys": sorted(info.keys()) if isinstance(info, dict) else None}
        if status != 200:
            raise ProbeError(f"encrypted GET /info returned {status}")
        log.info("    encrypted channel works (%d keys)", len(info))

        # Timing sockets: base (timing), base+1 (audio control), base+2 (audio data)
        timing_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        timing_sock.bind(("0.0.0.0", args.timing_port))
        timing = TimingResponder(timing_sock)
        timing.start()

        # 3. Control SETUP -------------------------------------------------
        log.info("[3] Control SETUP (timing=%s)", args.timing.upper())
        mac = random_mac()
        control = {
            "deviceID": mac, "macAddress": mac, "sessionUUID": session_uuid,
            "sourceVersion": SOURCE_VERSION, "isScreenMirroringSession": True,
            "timingProtocol": args.timing.upper(), "osBuildVersion": "13F69",
            "model": "Linux", "name": SENDER_NAME,
            "updateSessionRequest": False, "combinedGetInfoWithControlSetup": True,
        }
        if args.timing == "ntp":
            control["timingPort"] = args.timing_port
        else:
            peer = {"ID": str(uuid.uuid4()).upper(), "SupportsClockPortMatchingOverride": True,
                    "DeviceType": 0, "Addresses": [conn.local_ip]}
            control["timingPeerInfo"] = peer
            control["timingPeerList"] = [peer]
        status, rheaders, body = conn.request(
            "SETUP", audio_uri, {}, plistlib.dumps(control, fmt=plistlib.FMT_BINARY),
            "application/x-apple-binary-plist", timeout=args.setup_timeout)
        resp = decode_plist(body)
        steps["control_setup"] = {
            "status": status, "response": plist_summary(resp),
            "timing_requests_received_during_setup": timing.requests,
            "has_timingPeerInfo": isinstance(resp, dict) and "timingPeerInfo" in resp,
            "timingPeerInfo_ClockID": (resp.get("timingPeerInfo") or {}).get("ClockID") if isinstance(resp, dict) else None,
        }
        log.info("    response: %s", json.dumps(plist_summary(resp), default=str)[:1500])
        if status != 200:
            raise ProbeError(f"control SETUP returned {status}")
        if args.timing == "ptp" and not steps["control_setup"]["timingPeerInfo_ClockID"]:
            log.info("    NOTE: no timingPeerInfo.ClockID -- the failure doubletake reports on Samsung")
        if args.timing == "ntp" and resp.get("timingPort"):
            timing.probe_receiver(host, int(resp["timingPort"]))

        if resp.get("eventPort"):
            try:
                event = EventChannel(host, int(resp["eventPort"]), shared)
                event.start()
                steps["event_channel"] = "connected"
                log.info("    event channel connected on port %s", resp["eventPort"])
            except OSError as exc:
                steps["event_channel"] = f"failed: {exc}"

        if not resp.get("skipRecord"):
            status, _, _ = conn.request("RECORD", audio_uri,
                                        {"Session": session_uuid, "Range": "npt=0-",
                                         "RTP-Info": "seq=0;rtptime=0"})
            steps["record"] = status

        # 4. Video stream SETUP, no FairPlay ------------------------------
        def video_setup():
            video_sc_id = random.getrandbits(63)
            stream = {
                "type": 110, "streamConnectionID": video_sc_id, "latencyMs": 75,
                "timestampInfo": [{"name": n} for n in ("SubSu", "BePxT", "AfPxT", "BefEn", "EmEnc")],
                "shk": write_key[:16], "shiv": read_key[:16],
            }
            uri = f"rtsp://{host}:{AIRPLAY_PORT}/{video_sc_id}"
            result = conn.request("SETUP", uri, {},
                                  plistlib.dumps({"streams": [stream]}, fmt=plistlib.FMT_BINARY),
                                  "application/x-apple-binary-plist", timeout=args.setup_timeout)
            return result + (video_sc_id,)

        log.info("[4] Video stream SETUP (type 110, shk/shiv, no /fp-setup)")
        status, _, body, video_sc_id = video_setup()
        vresp = decode_plist(body)
        steps["video_setup"] = {"status": status, "response": plist_summary(vresp)}
        log.info("    response: %s", json.dumps(plist_summary(vresp), default=str)[:800])

        if status != 200 and not args.no_audio_retry:
            log.info("[4b] Video rejected alone; adding screen audio stream (type 96, ALAC) first")
            audio = {
                "type": 96, "streamConnectionID": audio_sc_id, "ct": 2, "spf": 352, "sr": 44100,
                "audioFormat": 0x40000, "audioMode": "default", "usingScreen": True,
                "latencyMin": 0, "latencyMax": int(0.085 * 44100),
                "controlPort": args.timing_port + 1, "shk": os.urandom(32),
            }
            astatus, _, abody = conn.request(
                "SETUP", audio_uri, {}, plistlib.dumps({"streams": [audio]}, fmt=plistlib.FMT_BINARY),
                "application/x-apple-binary-plist", timeout=args.setup_timeout)
            steps["audio_setup"] = {"status": astatus, "response": plist_summary(decode_plist(abody))}
            status, _, body, video_sc_id = video_setup()
            vresp = decode_plist(body)
            steps["video_setup_after_audio"] = {"status": status, "response": plist_summary(vresp)}
            log.info("    response: %s", json.dumps(plist_summary(vresp), default=str)[:800])

        data_port = None
        for stream in (vresp.get("streams") or []) if isinstance(vresp, dict) else []:
            if stream.get("type") == 110:
                data_port = stream.get("dataPort")
        if status == 200 and data_port:
            feedback = FeedbackLoop(conn)
            feedback.start()
            with socket.create_connection((host, int(data_port)), timeout=5) as data_sock:
                data_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                steps["data_port_connect"] = f"ok ({data_port})"
                if args.stream_seconds > 0:
                    width, height = (int(v) for v in args.size.lower().split("x"))
                    log.info("[5] Streaming %dx%d@%d test pattern for %ss (cipher=%s) -- watch the TV",
                             width, height, args.fps, args.stream_seconds, args.video_cipher)
                    streamer = MirrorStreamer(data_sock, args.video_cipher, shared, video_sc_id,
                                              write_key[:16], read_key[:16], width, height, args.fps,
                                              args.bitrate, lead=0.075)
                    steps["stream"] = streamer.run(args.stream_seconds)
                    log.info("    stream: %s", json.dumps(steps["stream"]))
                else:
                    log.info("    connected to video data port %s; holding %ss -- watch the TV", data_port, args.hold)
                    time.sleep(args.hold)
            feedback.stop.set()
            steps["feedback"] = {"sent": len(feedback.results),
                                 "statuses": sorted({str(r) for r in feedback.results})}
        else:
            steps["data_port_connect"] = "no dataPort in response"

    finally:
        if conn is not None and conn.cipher is not None:
            try:
                conn.request("TEARDOWN", audio_uri, {"Session": session_uuid}, timeout=5)
            except (ProbeError, OSError):
                pass
        if timing is not None:
            timing.stop.set()
            report["timing"] = {"requests_answered": timing.requests, "other_packets": timing.other,
                                "sources": sorted(timing.sources)}
        for c in (conn, event.conn if event else None):
            if c:
                c.close()
        if timing_sock:
            timing_sock.close()
        if event:
            report["events"] = event.received
        (run_dir / "report.json").write_text(json.dumps(report, indent=1, default=str))
        log.info("Report: %s", run_dir / "report.json")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--name", default="The Frame", help="regex matched against mDNS names")
    parser.add_argument("--host", help="skip discovery and use this IP")
    parser.add_argument("--pairing", choices=["auto", "transient", "pin"], default="auto")
    parser.add_argument("--hkp", type=int, choices=[HKP_PIN, HKP_SCREEN_CAPTURE], default=HKP_SCREEN_CAPTURE,
                        help="X-Apple-HKP type for PIN pairing (5 = screen capture)")
    parser.add_argument("--repair", action="store_true", help="ignore stored credentials and pair again")
    parser.add_argument("--timing", choices=["ntp", "ptp"], default="ntp")
    parser.add_argument("--timing-port", type=int, default=60000)
    parser.add_argument("--setup-timeout", type=float, default=10)
    parser.add_argument("--hold", type=float, default=5)
    parser.add_argument("--no-audio-retry", action="store_true")
    parser.add_argument("--stream-seconds", type=float, default=0, help="stage 2: stream a test pattern")
    parser.add_argument("--video-cipher", choices=["chacha", "aesctr", "none"], default="chacha")
    parser.add_argument("--size", default="1920x1080")
    parser.add_argument("--fps", type=int, default=30)
    parser.add_argument("--bitrate", type=int, default=6_000_000)
    parser.add_argument("--pin-file", type=Path, default=HERE / "pin")
    parser.add_argument("--pin-timeout", type=float, default=180)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    try:
        run(args)
    except ProbeError as exc:
        log.info("STOPPED: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
