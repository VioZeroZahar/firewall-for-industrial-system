from datetime import datetime
from firewall.packet import Packet

class TrafficGenerator:
    def __init__(self):
        self.scada_ip = "192.168.1.20"
        self.plc_ip = "192.168.1.10"
        self.modbus_port = 502

    def generate_read_packet(self):
        return Packet(
            source_ip=self.scada_ip,
            destination_ip=self.plc_ip,
            protocol="MODBUS",
            source_port=12345,
            destination_port=self.modbus_port,
            operation="READ",
            direction="SCADA_TO_PLC",
            timestamp=datetime.now()
        )

    def generate_write_packet(self):
        return Packet(
            source_ip=self.scada_ip,
            destination_ip=self.plc_ip,
            protocol="MODBUS",
            source_port=12345,
            destination_port=self.modbus_port,
            operation="WRITE",
            direction="SCADA_TO_PLC",
            timestamp=datetime.now()
        )

    def generate_unauthorized_packet(self):
        return Packet(
            source_ip="192.168.1.99",
            destination_ip=self.plc_ip,
            protocol="MODBUS",
            source_port=12345,
            destination_port=self.modbus_port,
            operation="READ",
            direction="SCADA_TO_PLC",
            timestamp=datetime.now()
        )

    def generate_invalid_port_packet(self):
        return Packet(
            source_ip=self.scada_ip,
            destination_ip=self.plc_ip,
            protocol="MODBUS",
            source_port=12345,
            destination_port=8080,
            operation="READ",
            direction="SCADA_TO_PLC",
            timestamp=datetime.now()
        )

    def generate_unsolicited_response_packet(self):
        return Packet(
            source_ip=self.plc_ip,
            destination_ip=self.scada_ip,
            protocol="MODBUS",
            source_port=self.modbus_port,
            destination_port=12345,
            operation="READ",
            direction="PLC_TO_SCADA",
            timestamp=datetime.now(),
            function_code=3,
            transaction_id=999
        )