#!/usr/bin/env python3
"""Offline test harness: creates synthetic packets but NEVER transmits them.

Use this to demonstrate detection logic in a controlled lab without sending
wireless deauthentication frames, ARP replies, or network probes.
"""
from detection import PacketDetector, SCAPY_AVAILABLE


def main():
    if not SCAPY_AVAILABLE:
        raise SystemExit('Scapy is required. Install it with: python -m pip install scapy')

    from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet import IP, TCP

    detector = PacketDetector(cooldown_seconds=0)
    packets = []

    # Synthetic deauthentication frames: constructed in memory only.
    for _ in range(5):
        packets.append(RadioTap() / Dot11(type=0, subtype=12,
                         addr1='00:11:22:33:44:55', addr2='02:00:00:00:00:01',
                         addr3='00:11:22:33:44:55') / Dot11Deauth(reason=7))

    # Synthetic ARP replies that advertise two MAC addresses for one test IP.
    packets.append(Ether() / ARP(op=2, psrc='192.0.2.10', hwsrc='02:00:00:00:00:10'))
    packets.append(Ether() / ARP(op=2, psrc='192.0.2.10', hwsrc='02:00:00:00:00:11'))

    # Synthetic TCP SYN packets for documentation-only TEST-NET address space.
    for port in (21, 22, 23, 80, 443):
        packets.append(IP(src='192.0.2.20', dst='192.0.2.30') / TCP(dport=port, flags='S'))
    for _ in range(100):
        packets.append(IP(src='192.0.2.40', dst='192.0.2.30') / TCP(dport=8080, flags='S'))

    print('OFFLINE DEMO — synthetic packets only; no packets will be transmitted.\n')
    for packet in packets:
        alert = detector.process(packet)
        if alert:
            print(f'[{alert.severity}] {alert.attack_type} | {alert.source} | {alert.details}')
    print('\nOffline demonstration complete.')


if __name__ == '__main__':
    main()
