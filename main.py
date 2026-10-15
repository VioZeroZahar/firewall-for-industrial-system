from firewall.rules import FirewallRule
from firewall.firewall import Firewall
from simulator.traffic_generator import TrafficGenerator
from simulator.attack_simulator import AttackSimulator

def main():
    rule = FirewallRule(
        name="Allow SCADA Read",
        allowed_source_ips=["192.168.1.20"],
        allowed_destination_ips=["192.168.1.10"],
        allowed_protocols=["MODBUS"],
        allowed_destination_ports=[502],
        allowed_operations=["READ"],
        allowed_directions=["SCADA_TO_PLC"]
    )

    firewall = Firewall([rule])
    generator=TrafficGenerator()

    print ("=== INDUSTRIAL FIREWALL SIMULATOR ===")

    print("\n--- Legitimate traffic ---")
    packet=generator.generate_read_packet()
    print(f"Packet: {packet}")
    print(f"Decision: {firewall.inspect_packet(packet)}")

    print("\n--- Attack simulation ---")
    simulator=AttackSimulator(firewall)
    simulator.run_attacks()

if __name__=="__main__":
    main()