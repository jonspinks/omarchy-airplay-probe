# airplay-probe

The protocol notebook behind [omarchy-airplay](https://github.com/jonspinks/omarchy-airplay):
a Python probe that worked out, against a real receiver, what a native AirPlay
screen-mirroring sender for Linux has to do. The Rust sender is the product;
this is where each step was first proven.

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

`--name` is a regex matched against the receivers' mDNS names; `--host IP`
skips discovery, which is unreliable across subnets. One of the two is required.
Each run writes `runs/<timestamp>/log.txt` and `report.json`.

## Secrets

- Long-term pairing keys are kept in `~/.config/airplay-probe/credentials.json`
  (`$XDG_CONFIG_HOME` if set), mode 0600, outside the checkout. A
  `credentials.json` left next to `probe.py` by an older version is moved
  there on the next run.
- `runs/` holds logs and reports with your receiver's identifiers (name,
  device ID, addresses). It is gitignored; scrub it before sharing a run.
- `pin` and `portal-session-token` are gitignored too.

## References

Protocol details were cross-checked against, not copied from:

- [pyatv](https://github.com/postlund/pyatv) (MIT) — HAP pairing, TLV8, framing.
- [doubletake](https://github.com/omarroth/doubletake) (LGPL-3.0) — mirroring
  SETUP sequence, data-channel packet layout, Samsung timing quirk.

Fetch copies into `ref/` when needed; they are not committed.

## License

MIT — see [LICENSE](LICENSE).
