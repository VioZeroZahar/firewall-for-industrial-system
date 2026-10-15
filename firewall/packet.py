from dataclasses import dataclass
from datetime import datetime

@dataclass
class Packet:
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int
    destination_port: int
    operation: str
    direction: str
    timestamp: datetime
    function_code: int = None
    transaction_id: int = None

    def is_write_operation(self):
        return self.operation.upper() == "WRITE"

    def is_read_operation(self):
        return self.operation.upper() == "READ"

    def to_dict(self):
        return {
            "source_ip": self.source_ip,
            "destination_ip":self.destination_ip,
            "protocol": self.protocol,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "operation": self.operation,
            "direction": self.direction,
            "timestamp": self.timestamp.isoformat(),
            "function_code": self.function_code,
            "transaction_id": self.transaction_id
        }

    def __str__(self):
        return (
            f"{self.source_ip}:{self.source_port} -> "
            f"{self.destination_ip}:{self.destination_port} | "
            f"{self.protocol} | {self.operation} | "
            f"Function code: {self.function_code} | "
            f"Transaction ID: {self.transaction_id} | "
            f"{self.direction}"
        )
