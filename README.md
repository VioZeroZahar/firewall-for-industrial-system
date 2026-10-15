# Industrial Firewall Simulator

A software-based firewall simulator designed for industrial networks using Modbus TCP. The project evaluates network packets against configurable security rules and blocks unauthorized or potentially unsafe communication.

## Features

- Rule-based packet filtering.
- Default-deny security policy: packets that do not match an allow rule are blocked.
- Filtering based on source IP, destination port, protocol, operation, and traffic direction.
- Detection and blocking of unauthorized source addresses.
- Blocking of unauthorized write operations.
- Detection of invalid destination ports.
- Detection of unsolicited PLC responses.
- Logging of firewall decisions.
- Offline analysis of PCAP network captures using Scapy.
- Automated tests using pytest.

## Project Structure

```text
SSI/
├── firewall/
│   ├── firewall.py
│   ├── logger.py
│   ├── packet.py
│   └── rules.py
├── simulator/
│   ├── attack_simulator.py
│   ├── pcap_reader.py
│   └── traffic_generator.py
├── tests/
│   └── test_firewall.py
├── logs/
├── main.py
├── test_attacks.py
├── test_pcap.py
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.11 or compatible Python 3 version
- Scapy 2.8.0
- pytest 9.1.1

## Installation

Clone the repository and open its directory:

```bash
git clone https://github.com/VioZeroZahar/firewall-for-industrial-system.git
cd firewall-for-industrial-system
```

Create and activate a virtual environment.

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Running the Simulator

Run the main simulation:

```bash
python main.py
```

Run the attack scenarios:

```bash
python test_attacks.py
```

The attack simulation includes unauthorized source addresses, unauthorized write operations, invalid destination ports, and unsolicited PLC responses.

## Running Automated Tests

Execute the test suite:

```bash
python -m pytest tests/test_firewall.py -v
```

The current test suite contains eight tests covering authorized traffic, blocked traffic, direction validation, and PLC response handling.

## PCAP Analysis

The project can analyze offline PCAP captures containing Modbus TCP traffic:

```bash
python test_pcap.py
```

The PCAP analysis script expects the dataset to be available at the path configured in the script. The dataset is not included in this repository and must be obtained separately.

## Security Model

The firewall follows a default-deny approach. A packet is allowed when it matches an applicable rule or qualifies as an authorized response to a previously permitted request. Unauthorized traffic is blocked and the decision can be recorded in the firewall log.

## Limitations

- The simulator is not a production-ready firewall and does not directly filter live network traffic.
- PCAP analysis does not currently perform TCP stream reassembly.
- Modbus TCP parsing and request-response validation are simplified.
- Authorized request tracking does not yet implement expiration timeouts.

## Disclaimer

This project is intended for educational and research purposes in industrial network cybersecurity.