from datetime import datetime
from pathlib import Path

class FirewallLogger:
    def __init__(self, log_file: str = "logs/firewall.log"):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log_decision(self, packet, decision):
        timestamp = datetime.now().isoformat()

        log_entry = (
            f"{timestamp} | "
            f"{decision['action']} | "
            f"{packet.source_ip}:{packet.source_port} -> "
            f"{packet.destination_ip}:{packet.destination_port} | "
            f"{packet.protocol} | "
            f"{packet.operation} | "
            f"{decision['reason']}\n"
        )

        with self.log_file.open("a", encoding="utf-8") as file:
            file.write(log_entry)