"""Packet-based detection rules for the wireless network monitor."""
from collections import defaultdict
from dataclasses import dataclass
import time
from typing import Optional

try:
    from scapy.layers.dot11 import Dot11, Dot11Deauth
    from scapy.layers.l2 import ARP
    from scapy.layers.inet import IP, TCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class Alert:
    timestamp: str
    attack_type: str
    source: str
    details: str
    severity: str


class PacketDetector:
    """Keeps detection state and returns alerts; it never sends packets."""

    def __init__(self, clock=time.time, alert_clock=None, cooldown_seconds=10):
        self.clock = clock
        self.alert_clock = alert_clock or (lambda: __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        self.cooldown_seconds = cooldown_seconds
        self.arp_table = {}
        self.deauth_counts = defaultdict(int)
        self.port_sets = defaultdict(set)
        self.syn_counts = defaultdict(int)
        self.last_alert = {}

    def _alert(self, kind, source, details, severity):
        key = (source, kind)
        now = self.clock()
        last = self.last_alert.get(key)
        if last is not None and now - last < self.cooldown_seconds:
            return None
        self.last_alert[key] = now
        return Alert(self.alert_clock(), kind, source, details, severity)

    def process(self, packet) -> Optional[Alert]:
        """Inspect one captured or offline-created Scapy packet."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError('Scapy is required for packet detection.')
        for check in (self._check_deauth, self._check_arp, self._check_syn):
            alert = check(packet)
            if alert:
                return alert
        return self._check_port_scan(packet)

    def _check_deauth(self, packet):
        if not packet.haslayer(Dot11Deauth) or not packet.haslayer(Dot11):
            return None
        source = packet[Dot11].addr2 or 'Unknown'
        self.deauth_counts[source] += 1
        count = self.deauth_counts[source]
        if count == 5:
            return self._alert('Deauthentication Activity', source,
                               f'{count} deauthentication frames observed from this source', 'HIGH')
        return None

    def _check_arp(self, packet):
        if not packet.haslayer(ARP) or packet[ARP].op != 2:
            return None
        source_ip, source_mac = packet[ARP].psrc, packet[ARP].hwsrc
        previous_mac = self.arp_table.get(source_ip)
        self.arp_table[source_ip] = source_mac
        if previous_mac and previous_mac != source_mac:
            return self._alert('Possible ARP Spoofing', source_mac,
                               f'IP {source_ip} changed MAC from {previous_mac} to {source_mac}', 'CRITICAL')
        return None

    def _check_port_scan(self, packet):
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return None
        tcp = packet[TCP]
        if int(tcp.flags) != 0x02:  # SYN without ACK
            return None
        source = packet[IP].src
        self.port_sets[source].add(int(tcp.dport))
        ports = self.port_sets[source]
        if len(ports) == 5:
            return self._alert('Possible Port Scan', source,
                               f'SYN packets observed for {len(ports)} distinct destination ports: {sorted(ports)}',
                               'MEDIUM')
        return None

    def _check_syn(self, packet):
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return None
        if int(packet[TCP].flags) != 0x02:
            return None
        source = packet[IP].src
        self.syn_counts[source] += 1
        count = self.syn_counts[source]
        if count == 100 or (count > 100 and count % 200 == 0):
            return self._alert('High SYN Volume', source,
                               f'{count} TCP SYN packets observed from this source; investigate traffic context', 'HIGH')
        return None
