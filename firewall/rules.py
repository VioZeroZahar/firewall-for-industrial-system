from dataclasses import dataclass
from firewall.packet import Packet


@dataclass
class FirewallRule:
    # Reprezintă o regulă care stabilește dacă un pachet este permis.
    name: str
    allowed_source_ips: list[str]
    allowed_destination_ips: list[str]
    allowed_protocols: list[str]
    allowed_destination_ports: list[int]
    allowed_operations: list[str]
    allowed_directions: list[str]

    # Verifică dacă pachetul respectă toate condițiile regulii.
    def matches(self, packet: Packet):
        if packet.source_ip not in self.allowed_source_ips:
            return False

        if packet.destination_ip not in self.allowed_destination_ips:
            return False

        if packet.protocol.upper() not in [
            protocol.upper() for protocol in self.allowed_protocols
        ]:
            return False

        if packet.destination_port not in self.allowed_destination_ports:
            return False

        if packet.operation.upper() not in [
            operation.upper() for operation in self.allowed_operations
        ]:
            return False

        if packet.direction.upper() not in [
            direction.upper() for direction in self.allowed_directions
        ]:
            return False

        return True

    def get_failure_reason(self, packet: Packet):
        if packet.source_ip not in self.allowed_source_ips:
            return "SOURCE_IP_NOT_ALLOWED"

        if packet.destination_ip not in self.allowed_destination_ips:
            return "DESTINATION_IP_NOT_ALLOWED"

        if packet.protocol.upper() not in [
            protocol.upper() for protocol in self.allowed_protocols
        ]:
            return "PROTOCOL_NOT_ALLOWED"

        if packet.destination_port not in self.allowed_destination_ports:
            return "DESTINATION_PORT_NOT_ALLOWED"

        if packet.operation.upper() not in [
            operation.upper() for operation in self.allowed_operations
        ]:
            return "OPERATION_NOT_ALLOWED"

        if packet.direction.upper() not in [
            direction.upper() for direction in self.allowed_directions
        ]:
            return "DIRECTION_NOT_ALLOWED"

        return None