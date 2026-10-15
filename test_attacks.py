from firewall.packet import Packet
from firewall.rules import FirewallRule
from firewall.firewall import Firewall
from simulator.attack_simulator import AttackSimulator

rule = FirewallRule (
    name = "Allow SCADA Read",
    allowed_source_ips = ["192.168.1.20"],
    allowed_destination_ips = ["192.168.1.10"],
    allowed_protocols = ["MODBUS"],
    allowed_destination_ports = [502],
    allowed_operations = ["READ"],
    allowed_directions = ["SCADA_TO_PLC"]
)

firewall = Firewall([rule])

simulator = AttackSimulator(firewall)
results = simulator.run_attacks()

print("\n --- SUMMARY ---")

for result in results:
    print(
        f"{result['attack']}: "
        f"{result['action']} - {result['reason']}"
    )