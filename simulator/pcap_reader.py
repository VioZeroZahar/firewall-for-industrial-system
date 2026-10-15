from scapy.all import PcapReader, IP, TCP
from datetime import datetime
from firewall.packet import Packet

class PcapReaderService:
    def __init__(self, file_path):
        self.file_path = file_path

    # Identifica mesajele Modbus TCP.
    def decode_modbus_payload(self, payload):
        messages = []
        offset = 0

        while len(payload) - offset >= 8:
            transaction_id = int.from_bytes(payload[offset:offset+2], "big")

            protocol_id = int.from_bytes(payload[offset + 2:offset + 4], "big")

            length = int.from_bytes(payload[offset + 4:offset + 6], "big")

            total_length = 6 + length

            if (
                protocol_id != 0
                or length < 2
                or total_length > len(payload) - offset
            ):
                break

            function_code = payload[offset + 7]
            base_code = function_code & 0x7F

            if base_code in [1, 2, 3, 4]:
                operation = "READ"
            elif base_code in [5, 6, 15, 16, 22]:
                operation = "WRITE"
            elif base_code == 23:
                operation = "READ_WRITE"
            else:
                operation = "OTHER"

            messages.append({
                "transaction_id": transaction_id,
                "function_code": function_code,
                "operation": operation
            })

            offset += total_length

        return messages

    def create_packet(self, captured_packet, message):
        source_port = captured_packet[TCP].sport
        destination_port = captured_packet[TCP].dport

        if destination_port == 502:
            direction = "SCADA_TO_PLC"
        elif source_port == 502:
            direction = "PLC_TO_SCADA"
        else:
            direction = "UNKNOWN"

        return Packet(
            source_ip=captured_packet[IP].src,
            destination_ip=captured_packet[IP].dst,
            protocol="MODBUS",
            source_port=source_port,
            destination_port=destination_port,
            operation=message["operation"],
            direction=direction,
            timestamp=datetime.fromtimestamp(float(captured_packet.time)),
            function_code=message["function_code"],
            transaction_id=message["transaction_id"]
        )

    # Analizeaza captura si limiteaza numarul de pachete citite.
    def inspect_capture(self, firewall, max_packets=5000, max_messages=30):
        packets_scanned = 0
        messages_found = 0
        decisions=[]

        with PcapReader(self.file_path) as capture:
            for captured_packet in capture:
                if packets_scanned >= max_packets:
                    break

                packets_scanned += 1

                if IP not in captured_packet or TCP not in captured_packet:
                    continue

                if (
                    captured_packet[TCP].sport != 502
                    and captured_packet[TCP].dport != 502
                ):
                    continue

                payload = bytes(captured_packet[TCP].payload)

                if not payload:
                    continue

                messages = self.decode_modbus_payload(payload)

                for message in messages:
                    packet=self.create_packet(captured_packet, message)

                    decision = firewall.inspect_packet(packet)

                    print(f"\nPacket: {packet}")
                    print(f"Function code: {packet.function_code}")
                    print(f"Transaction ID: {packet.transaction_id}")
                    print(f"Firewall action: {decision['action']}")
                    print(f"Reason: {decision['reason']}")

                    decisions.append({
                        "packet": packet,
                        "decision": decision
                    })

                    messages_found += 1

                    if messages_found >= max_messages:
                        break

                if messages_found >= max_messages:
                    break

        print(f"\nPackets analyzed: {packets_scanned}")
        print(f"MODBUS messages identified: {messages_found}")

        return decisions