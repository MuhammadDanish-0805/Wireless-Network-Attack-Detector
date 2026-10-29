#!/usr/bin/env python3
"""GUI for monitoring captured network packets and displaying alerts."""
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
from pathlib import Path

try:
    from scapy.all import AsyncSniffer, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from detection import PacketDetector
from alert_logger import AlertLogger

BG = '#0d1117'
PANEL = '#161b22'
TEXT = '#c9d1d9'
MUTED = '#8b949e'
BLUE = '#58a6ff'


class WirelessDetectorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Wireless Network Attack Detector')
        self.geometry('980x700')
        self.configure(bg=BG)
        self.detector = PacketDetector()
        self.logger = AlertLogger()
        self.sniffer = None
        self.alert_counts = {'total': 0, 'HIGH': 0, 'CRITICAL': 0, 'MEDIUM': 0}
        self._build_ui()
        self.protocol('WM_DELETE_WINDOW', self._on_close)

    def _build_ui(self):
        header = tk.Frame(self, bg=PANEL, pady=12)
        header.pack(fill='x')
        tk.Label(header, text='🛡  Wireless Attack Detector', font=('Courier New', 18, 'bold'),
                 fg=BLUE, bg=PANEL).pack(side='left', padx=20)
        tk.Label(header, text='Wireless Network Security', font=('Courier New', 10),
                 fg=MUTED, bg=PANEL).pack(side='right', padx=20)

        controls = tk.Frame(self, bg=BG, pady=8)
        controls.pack(fill='x', padx=16)
        tk.Label(controls, text='Interface:', font=('Courier New', 10), fg=TEXT, bg=BG).pack(side='left')
        interfaces = get_if_list() if SCAPY_AVAILABLE else []
        self.interface = tk.StringVar(value=interfaces[0] if interfaces else '')
        self.interface_box = ttk.Combobox(controls, textvariable=self.interface, values=interfaces,
                                           width=18, state='readonly')
        self.interface_box.pack(side='left', padx=8)
        self.start_button = tk.Button(controls, text='▶ Start Detection', bg='#238636', fg='white',
                                      relief='flat', command=self.start_detection)
        self.start_button.pack(side='left', padx=4)
        self.stop_button = tk.Button(controls, text='■ Stop', bg='#da3633', fg='white',
                                     relief='flat', state='disabled', command=self.stop_detection)
        self.stop_button.pack(side='left', padx=4)
        tk.Button(controls, text='Clear Alerts', bg='#30363d', fg=TEXT, relief='flat',
                  command=self.clear_alerts).pack(side='left', padx=4)
        tk.Button(controls, text='Test Alert', bg='#6e40c9', fg='white', relief='flat',
                  command=self.inject_test_alert).pack(side='left', padx=4)
        self.status = tk.Label(controls, text='● IDLE', font=('Courier New', 10, 'bold'), fg=MUTED, bg=BG)
        self.status.pack(side='right', padx=8)

        stats = tk.Frame(self, bg=BG, pady=4)
        stats.pack(fill='x', padx=16)
        self.stat_labels = {}
        for key, label, color in [('total', 'Total Alerts', BLUE), ('CRITICAL', 'Critical', '#f85149'),
                                  ('HIGH', 'High', '#d29922'), ('MEDIUM', 'Medium', '#3fb950')]:
            card = tk.Frame(stats, bg=PANEL, padx=16, pady=8)
            card.pack(side='left', padx=(0, 8))
            value = tk.Label(card, text='0', font=('Courier New', 20, 'bold'), fg=color, bg=PANEL)
            value.pack()
            tk.Label(card, text=label, font=('Courier New', 8), fg=MUTED, bg=PANEL).pack()
            self.stat_labels[key] = value

        table_frame = tk.Frame(self, bg=BG)
        table_frame.pack(fill='both', expand=True, padx=16, pady=(8, 0))
        tk.Label(table_frame, text='ALERTS', font=('Courier New', 10, 'bold'), fg=MUTED, bg=BG).pack(anchor='w')
        columns = ('Timestamp', 'Attack Type', 'Severity', 'Source', 'Details')
        self.table = ttk.Treeview(table_frame, columns=columns, show='headings', height=14)
        for column, width in zip(columns, (145, 180, 85, 150, 360)):
            self.table.heading(column, text=column)
            self.table.column(column, width=width, anchor='w')
        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        self.table.pack(fill='both', expand=True)
        for severity, color in [('CRITICAL', '#f85149'), ('HIGH', '#d29922'), ('MEDIUM', '#3fb950')]:
            self.table.tag_configure(severity, foreground=color)

        log_frame = tk.Frame(self, bg=BG)
        log_frame.pack(fill='x', padx=16, pady=8)
        tk.Label(log_frame, text='SYSTEM LOG', font=('Courier New', 10, 'bold'), fg=MUTED, bg=BG).pack(anchor='w')
        self.log_box = scrolledtext.ScrolledText(log_frame, height=5, bg=PANEL, fg=MUTED,
                                                 font=('Courier New', 9), relief='flat', state='disabled')
        self.log_box.pack(fill='x')
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Treeview', background=PANEL, foreground=TEXT, fieldbackground=PANEL,
                        rowheight=26, font=('Courier New', 9))
        style.configure('Treeview.Heading', background='#21262d', foreground=BLUE,
                        font=('Courier New', 9, 'bold'))

    def start_detection(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror('Dependency missing', 'Install Scapy first: python -m pip install scapy')
            return
        interface = self.interface.get().strip()
        if not interface:
            messagebox.showwarning('Select interface', 'Choose a network interface first.')
            return
        try:
            self.sniffer = AsyncSniffer(iface=interface, prn=self._handle_packet, store=False)
            self.sniffer.start()
        except Exception as error:
            self.sniffer = None
            messagebox.showerror('Could not start capture', str(error))
            return
        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.status.config(text='● MONITORING', fg='#3fb950')
        self.log(f'Started packet capture on interface: {interface}')
        self.log('Detection rules: deauthentication activity, ARP changes, port scans, high SYN volume')

    def _handle_packet(self, packet):
        try:
            alert = self.detector.process(packet)
            if alert:
                self.logger.write(alert)
                self.after(0, self.add_alert, alert)
        except Exception as error:
            self.after(0, self.log, f'Packet processing error: {error}')

    def stop_detection(self):
        if self.sniffer and self.sniffer.running:
            try:
                self.sniffer.stop()
            except Exception as error:
                self.log(f'Capture stop warning: {error}')
        self.sniffer = None
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.status.config(text='● STOPPED', fg='#f85149')
        self.log(f'Stopped. Total alerts: {self.alert_counts["total"]}')
        self.log(f'CSV log: {Path(self.logger.path).resolve()}')

    def inject_test_alert(self):
        from detection import Alert
        alert = Alert(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'GUI Test Alert',
                      'TEST-ONLY', 'This synthetic alert confirms that the GUI is working.', 'MEDIUM')
        self.logger.write(alert)
        self.add_alert(alert)
        self.log('Synthetic test alert added; no network packets were sent.')

    def add_alert(self, alert):
        self.table.insert('', 0, values=(alert.timestamp, alert.attack_type, alert.severity,
                                         alert.source, alert.details), tags=(alert.severity,))
        self.alert_counts['total'] += 1
        if alert.severity in self.alert_counts:
            self.alert_counts[alert.severity] += 1
        for key, label in self.stat_labels.items():
            label.config(text=str(self.alert_counts[key]))
        self.log(f'ALERT [{alert.severity}] {alert.attack_type} — {alert.source}')

    def clear_alerts(self):
        for row in self.table.get_children():
            self.table.delete(row)
        for key in self.alert_counts:
            self.alert_counts[key] = 0
        for label in self.stat_labels.values():
            label.config(text='0')
        self.log('Visible alerts cleared. The CSV log was not deleted.')

    def log(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_box.config(state='normal')
        self.log_box.insert('end', f'[{timestamp}] {message}\n')
        self.log_box.see('end')
        self.log_box.config(state='disabled')

    def _on_close(self):
        self.stop_detection()
        self.destroy()


if __name__ == '__main__':
    WirelessDetectorApp().mainloop()
