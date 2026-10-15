from simulator.pcap_reader import PcapReaderService
from firewall.rules import FirewallRule
from firewall.firewall import Firewall

pcap_path = (
    r"D:\PyCharm\python\SSI\dataset\Modbus Dataset\attack"
    r"\external\network-wide\network-wide-normal-0.pcap"
)

rule = FirewallRule(
    name="Allow Authorized SCADA Read",
    allowed_source_ips=["185.175.0.3"],
    allowed_destination_ips=["185.175.0.4"],
    allowed_protocols=["MODBUS"],
    allowed_destination_ports=[502],
    allowed_operations=["READ"],
    allowed_directions=["SCADA_TO_PLC"]
)

firewall = Firewall(rules=[rule])

reader = PcapReaderService(pcap_path)

reader.inspect_capture(firewall=firewall, max_packets=5000, max_messages=30)