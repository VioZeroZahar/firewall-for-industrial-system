from datetime import datetime
from os import times
import time
from firewall.packet import Packet
from firewall.rules import FirewallRule
from firewall.firewall import Firewall

def create_test_firewall():
    rule = FirewallRule(
        name="Allow SCADA Read",
        allowed_source_ips=["192.168.1.20"],
        allowed_destination_ips=["192.168.1.10"],
        allowed_protocols=["MODBUS"],
        allowed_destination_ports=[502],
        allowed_operations=["READ"],
        allowed_directions=["SCADA_TO_PLC"]
    )

    return Firewall(rules=[rule])

def create_packet(
        source_ip="192.168.1.20",
        destination_ip="192.168.1.10",
        destination_port=502,
        operation="READ",
        direction="SCADA_TO_PLC"
):
    return Packet(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol="MODBUS",
        source_port=12345,
        destination_port=destination_port,
        operation=operation,
        direction=direction,
        timestamp=datetime.now(),
        function_code=3,
        transaction_id=1
    )

def test_authorized_read_is_allowed():
    firewall=create_test_firewall()
    packet=create_packet()

    decision=firewall.inspect_packet(packet)

    assert decision["action"] == "ALLOW"

def test_unauthorized_ip_is_blocked():
    firewall=create_test_firewall()
    packet=create_packet(source_ip="192.168.1.99")

    decision=firewall.inspect_packet(packet)

    assert decision["action"]=="BLOCK"

def test_write_operation_is_blocked():
    firewall=create_test_firewall()
    packet=create_packet(operation="WRITE")

    decision=firewall.inspect_packet(packet)

    assert decision["action"]=="BLOCK"

def test_invalid_port_is_blocked():
    firewall=create_test_firewall()
    packet=create_packet(destination_port=8080)

    decision=firewall.inspect_packet(packet)

    assert decision["action"]=="BLOCK"

def test_wrong_direction_is_blocked():
    firewall=create_test_firewall()
    packet=create_packet(direction="PLC_TO_SCADA")

    decision=firewall.inspect_packet(packet)

    assert decision["action"]=="BLOCK"

def test_athorized_plc_response_is_allowed():
    firewall=create_test_firewall()

    request=create_packet()
    request_decision=firewall.inspect_packet(request)

    response=Packet(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        protocol="MODBUS",
        source_port=502,
        destination_port=12345,
        operation="READ",
        direction="PLC_TO_SCADA",
        timestamp=datetime.now(),
        function_code=3,
        transaction_id=1
    )

    response_decision=firewall.inspect_packet(response)

    assert request_decision["action"]=="ALLOW"
    assert response_decision["action"]=="ALLOW"
    assert response_decision["rule"]=="Authorized PLC Response"

def test_unsolicited_plc_response_is_blocked():
    firewall=create_test_firewall()

    response=Packet(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        protocol="MODBUS",
        source_port=502,
        destination_port=12345,
        operation="READ",
        direction="PLC_TO_SCADA",
        timestamp=datetime.now(),
        function_code=3,
        transaction_id=99
    )

    decision=firewall.inspect_packet(response)

    assert decision["action"]=="BLOCK"

def test_response_with_wrong_function_code_is_blocked():
    firewall=create_test_firewall()

    request=create_packet()
    firewall.inspect_packet(request)

    response=Packet(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        protocol="MODBUS",
        source_port=502,
        destination_port=12345,
        operation="READ",
        direction="PLC_TO_SCADA",
        timestamp=datetime.now(),
        function_code=4,
        transaction_id=1
    )

    decision=firewall.inspect_packet(response)

def test_expired_request_response_is_blocked():
    firewall = create_test_firewall()
    firewall.request_timeout = 0.01

    request = create_packet()
    request_decision = firewall.inspect_packet(request)

    assert request_decision["action"] == "ALLOW"

    time.sleep(0.02)

    response = Packet(
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        protocol="MODBUS",
        source_port=502,
        destination_port=12345,
        operation="READ",
        direction="PLC_TO_SCADA",
        timestamp=datetime.now(),
        function_code=3,
        transaction_id=1
    )

    response_decision = firewall.inspect_packet(response)

    assert response_decision["action"] == "BLOCK"
    assert response_decision["reason"] == "UNSOLICITED_PLC_RESPONSE"