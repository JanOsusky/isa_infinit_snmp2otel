#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
from pysnmp.hlapi.asyncio import *
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading

# -----------------------------
# 1️⃣ Falešný SNMPv2c server
# -----------------------------

# Testovací OID -> hodnota
oids = {
    '1.3.6.1.2.1.1.3.0': 12345,  # sysUpTime
    '1.3.6.1.2.1.1.5.0': 'FakeHost'  # sysName
}

class SNMPResponder:
    def __init__(self, ip='127.0.0.1', port=1161, community='public'):
        self.ip = ip
        self.port = port
        self.community = community

    async def run(self):
        snmpEngine = SnmpEngine()
        # UDP listener
        transportDispatcher = AsyncioDispatcher()
        transportDispatcher.registerTransport(
            udp.domainName, udp.UdpSocketTransport().openServerMode((self.ip, self.port))
        )
        transportDispatcher.jobStarted(1)

        print(f"[SNMP] Fake SNMP server listening on {self.ip}:{self.port}")

        # Keep alive
        while True:
            await asyncio.sleep(1)

# -----------------------------
# 2️⃣ Falešný OTEL HTTP endpoint
# -----------------------------

class FakeOTELHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/v1/metrics":
            length = int(self.headers['Content-Length'])
            body = self.rfile.read(length)
            try:
                data = json.loads(body)
                print("\n[OTEL] Received metrics JSON:\n", json.dumps(data, indent=2))
            except Exception as e:
                print("[OTEL] Failed to parse JSON:", e)
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

def run_otel_server(ip='127.0.0.1', port=8080):
    server = HTTPServer((ip, port), FakeOTELHandler)
    print(f"[OTEL] Fake OTEL endpoint running on http://{ip}:{port}/v1/metrics")
    server.serve_forever()

# -----------------------------
# 3️⃣ Spuštění obou služeb
# -----------------------------

if __name__ == "__main__":
    # Spustíme OTEL server v samostatném vlákně
    otel_thread = threading.Thread(target=run_otel_server, args=('127.0.0.1', 8080), daemon=True)
    otel_thread.start()

    # Spustíme SNMP server v asyncio event loop
    snmp_server = SNMPResponder(ip='127.0.0.1', port=1161)
    asyncio.run(snmp_server.run())
