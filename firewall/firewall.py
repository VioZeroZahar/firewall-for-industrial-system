from firewall.packet import Packet
from firewall.rules import FirewallRule
from firewall.logger import FirewallLogger


class Firewall:
    # Inițializează firewall-ul cu regulile, politica implicită și logger-ul.
    def __init__(
        self,
        rules: list[FirewallRule],
        default_action: str = "BLOCK",
        logger: FirewallLogger = None
    ):
        self.rules = rules
        self.default_action = default_action.upper()
        self.logger = logger if logger is not None else FirewallLogger()

        self.authorized_requests = {}

    def _request_key(self, packet: Packet):
        return (
            packet.source_ip,
            packet.destination_ip,
            packet.source_port,
            packet.destination_port,
            packet.transaction_id
        )

    def _response_matches_authorized_request(self, packet: Packet):
        if packet.direction != "PLC_TO_SCADA":
            return False

        if packet.transaction_id is None:
            return False

        request_key = (
            packet.destination_ip,
            packet.source_ip,
            packet.destination_port,
            packet.source_port,
            packet.transaction_id
        )

        request_function=self.authorized_requests.get(request_key)

        if request_function is None:
            return False

        response_function=packet.function_code

        if response_function is None:
            return False

        is_exception=bool(response_function & 0x80)
        expected_function=request_function & 0x7F

        if is_exception:
            return (response_function & 0x7F) == expected_function

        return response_function == expected_function

    def _is_unsolicited_response(self, packet: Packet):
        if packet.direction != "PLC_TO_SCADA":
            return False

        return not self._response_matches_authorized_request(packet)
    def inspect_packet(self, packet: Packet):
        if self._response_matches_authorized_request(packet):
            decision = {
                "action": "ALLOW",
                "rule": "Authorized PLC Response",
                "reason": "Response matches an authorized request"
            }

            self.logger.log_decision(packet,decision)

            request_key=(
                packet.destination_ip,
                packet.source_ip,
                packet.destination_port,
                packet.source_port,
                packet.transaction_id
            )

            self.authorized_requests.pop(request_key, None)
            return decision

        if self._is_unsolicited_response(packet):
            decision = {
                "action": "BLOCK",
                "rule": None,
                "reason": "UNSOLICITED_PLC_RESPONSE"
            }

            self.logger.log_decision(packet, decision)
            return decision

        for rule in self.rules:
            if rule.matches(packet):
                decision = {
                    "action": "ALLOW",
                    "rule": rule.name,
                    "reason": f"Packet matched rule: {rule.name}"
                }

                if (
                    packet.direction == "SCADA_TO_PLC"
                    and packet.transaction_id is not None
                    and packet.function_code is not None
                ):
                    self.authorized_requests[self._request_key(packet)]=packet.function_code

                self.logger.log_decision(packet, decision)
                return decision

        if self.rules:
            reason = self.rules[0].get_failure_reason(packet)
        else:
            reason = "NO_RULES_CONFIGURED"

        decision = {
            "action": self.default_action,
            "rule": None,
            "reason": reason
        }

        self.logger.log_decision(packet, decision)
        return decision