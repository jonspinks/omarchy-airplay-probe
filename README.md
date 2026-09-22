# airplay-probe

Throwaway investigation tool for a native AirPlay screen-mirroring sender for
Omarchy. Not the product — the product will be a Rust daemon built from what
this probe proves.

## Result (2026-09-15)

A Samsung Frame (LS03F, AirPlay SDK 3.6.0.72, sourceVersion 377.40.00)
displays video from this probe with **no FairPlay**:

1. Transient HAP pairing (`X-Apple-HKP: 4`, no PIN).
2. HAP-encrypted control channel (`Control-Salt` keys).
3. Screen-mirroring control SETUP with **NTP** timing (PTP is accepted but
   returns no `timingPeerInfo.ClockID` on this firmware), then RECORD.
4. Type-110 stream SETUP, TCP data channel, `POST /feedback` every 2 s.
5. H.264 access units encrypted with ChaCha20-Poly1305 using
   `HKDF-SHA512(K, "DataStream-Salt<streamConnectionID>",
   "DataStream-Output-Encryption-Key")`, 128-byte header as AAD.

## Running

```sh
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python probe.py --name '^Demo TV$' --stream-seconds 20
```

`--host IP` skips mDNS discovery, which is unreliable across subnets.
Each run writes `runs/<timestamp>/log.txt` and `report.json`.

## References

Protocol details were cross-checked against, not copied from:

- [pyatv](https://github.com/postlund/pyatv) (MIT) — HAP pairing, TLV8, framing.
- [doubletake](https://github.com/omarroth/doubletake) (LGPL-3.0) — mirroring
  SETUP sequence, data-channel packet layout, Samsung timing quirk.

Fetch copies into `ref/` when needed; they are not committed.
