from simulator.traffic_generator import TrafficGenerator

class AttackSimulator:
    def __init__(self, firewall):
        self.firewall = firewall
        self.generator = TrafficGenerator()

    def run_attacks(self):
        attacks = [
            ("Unauthorized IP", self.generator.generate_unauthorized_packet()),
            ("Unauthorized WRITE", self.generator.generate_write_packet()),
            ("Invalid destination port", self.generator.generate_invalid_port_packet()),
            ("unsolicited PLC response", self.generator.generate_unsolicited_response_packet()),
        ]

        results = []

        for attack_name, packet in attacks:
            decision = self.firewall.inspect_packet(packet)

            result = {
                "attack": attack_name,
                "packet": str(packet),
                "action": decision["action"],
                "reason": decision["reason"]
            }

            results.append(result)

            print(f"\nAttack: {attack_name}")
            print(f"Packet: {packet}")
            print(f"Firewall action: {decision['action']}")
            print(f"Reason: {decision['reason']}")

        return results