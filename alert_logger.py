"""CSV logging for detector alerts."""
import csv
from pathlib import Path

HEADERS = ['Timestamp', 'Attack Type', 'Source', 'Details', 'Severity']

class AlertLogger:
    def __init__(self, path='alerts_log.csv'):
        self.path = Path(path)
        self._ensure_file()

    def _ensure_file(self):
        if not self.path.exists():
            with self.path.open('w', newline='', encoding='utf-8') as handle:
                csv.writer(handle).writerow(HEADERS)

    def write(self, alert):
        with self.path.open('a', newline='', encoding='utf-8') as handle:
            csv.writer(handle).writerow([
                alert.timestamp, alert.attack_type, alert.source,
                alert.details, alert.severity,
            ])
