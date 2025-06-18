#!/usr/bin/env python3
"""
DNS C2 Server Simulator con chunking dei record TXT

Simula un server DNS locale (UDP/TCP 53) basato su un file "zone_records.txt".
Supporta record A e TXT per:
  - domini autorizzati (A)
  - record _auth.<host> TXT chunked in segmenti <=255 byte

Formato "zone_records.txt":
  nome [A|TXT] valore
Esempi:
  90435712c965.com A 127.0.0.1
  _auth.90435712c965.com TXT eyJob3N0Ijoi..."  # base64 JSON lungo

Uso:
  sudo python3 dns_c2_server_simulator.py
"""
from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, QTYPE, A, TXT, RCODE
from pathlib import Path
import threading

# Config
ZONE_FILE = Path("zone_records.txt")
LISTEN_ADDR = "0.0.0.0"
PORT = 53
DEFAULT_TTL = 60
MAX_TXT_SEGMENT = 255  # dimensione massima per segmento TXT

# Chunking funzione
def chunk_txt(txt: str) -> list[str]:
    b = txt.encode()
    return [b[i:i+MAX_TXT_SEGMENT].decode() for i in range(0, len(b), MAX_TXT_SEGMENT)]

class ZoneResolver(BaseResolver):
    def __init__(self, zone_file):
        self.zone_file = Path(zone_file)
        self.load_zone()

    def load_zone(self):
        self.a_records = {}
        self.txt_records = {}
        if not self.zone_file.exists():
            print(f"[!] Zone file {self.zone_file} non trovato.")
            return
        for line in self.zone_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#'): continue
            parts = line.split(None, 2)
            if len(parts) != 3: continue
            name, typ, val = parts
            name = name.rstrip('.').lower()
            if typ.upper() == 'A':
                self.a_records.setdefault(name, []).append(val)
            elif typ.upper() == 'TXT':
                # rimuove virgolette
                txtval = val.strip('"')
                segments = chunk_txt(txtval)
                self.txt_records.setdefault(name, []).append(segments)
        print(f"[+] Loaded {len(self.a_records)} A records, {len(self.txt_records)} TXT records.")

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip('.').lower()
        qtype = QTYPE[request.q.qtype]
        # reload zona
        self.load_zone()
        reply = request.reply()

        if qtype == 'A' and qname in self.a_records:
            for ip in self.a_records[qname]:
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=DEFAULT_TTL))
            print(f"[A] {qname} -> {self.a_records[qname]}")
            return reply

        if qtype == 'TXT' and qname in self.txt_records:
            for segments in self.txt_records[qname]:
                # TXT(*segments) crea un record chunked
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(segments), ttl=DEFAULT_TTL))
            print(f"[TXT] {qname} -> chunked TXT ({len(self.txt_records[qname])} entry)")
            return reply

        # NXDOMAIN
        reply.header.rcode = RCODE.NXDOMAIN
        print(f"[NXDOMAIN] {qname}")
        return reply

if __name__ == '__main__':
    resolver = ZoneResolver(ZONE_FILE)
    server = DNSServer(resolver, port=PORT, address=LISTEN_ADDR)
    print(f"[*] DNS C2 Simulator in ascolto su {LISTEN_ADDR}:{PORT}")
    try:
        server.start_thread()
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[!] Terminato by user.")
        server.stop()
