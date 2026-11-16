import csv
from collections import Counter
from pathlib import Path
from firewall.firewall import Firewall
from firewall.rules import FirewallRule
from simulator.pcap_reader import PcapReaderService

DATASET_DIR = Path("dataset") / "Modbus Dataset"
REPORT_DIR = Path("reports")

MAX_PACKETS_PER_CAPTURE = 5000

def create_firewall():
    rule = FirewallRule(
        name="Allow Authorized SCADA Read",
        allowed_source_ips=["192.168.0.3"],
        allowed_destination_ips=["192.175.0.4"],
        allowed_protocols=["MODBUS"],
        allowed_destination_ports=[502],
        allowed_operations=["READ"],
        allowed_directions=["SCADA_TO_PLC"]
    )

    return Firewall(rules=[rule])

def evaluate_capture(pcap_path, category):
    firewall = create_firewall()
    reader = PcapReaderService(str(pcap_path))
    stats = Counter()
    reasons = Counter()
    error_message = ""

    try:
        decisions = reader.inspect_capture(
            firewall = firewall,
            max_packets=MAX_PACKETS_PER_CAPTURE,
            max_messages=10**9
        )

        stats["messages"] = len(decisions)

        for item in decisions:
            decision = item["decision"]
            action = str(decision.get("action", "UNKNOWN")).upper()
            reason = str(decision.get("reason", "UNKNOWN"))

            if action == "ALLOW":
                stats["allowed"] +=1
            elif action == "BLOCK":
                stats["blocked"] +=1
                reasons[reason] +=1
            else:
                stats["unknown"] +=1

    except Exception as exc:
        error_message = f"{type(exc).__name__}: {exc}"
        stats["errors"] +=1

    return {
        "category": category,
        "file": str(pcap_path.relative_to(DATASET_DIR)),
        "messages": stats["messages"],
        "allowed": stats["allowed"],
        "blocked": stats["blocked"],
        "unknown": stats["unknown"],
        "errors": stats["errors"],
        "block_reasons": "; ".join(
            f"{reason}: {count}"
            for reason, count in reasons.items()
        ),
        "error_details": error_message
    }

def main():
    REPORT_DIR.mkdir(exist_ok=True)

    results = []
    capture_counts = Counter()

    for category in ("benign", "attack"):
        category_dir = DATASET_DIR / category

        if not category_dir.exists():
            print(f"Directory does not exist: {category-dir}")
            continue

        pcap_files = sorted(category_dir.rglob("*.pcap"))
        print(f"\nCategory {category}: {len(pcap_files)} captures")

        for index, pcap_path in enumerate(pcap_files, start=1):
            result = evaluate_capture(pcap_path, category)
            results.append(result)
            capture_counts[category] +=1

            print(
                f"[{index}/{len(pcap_files)}] "
                f"{pcap_path.name} | "
                f"messages={result['messages']} | "
                f"ALLOW={result['allowed']} | "
                f"BLOCK={result['blocked']} | "
                f"errors={result['errors']}"
            )

    report_path = REPORT_DIR / "dataset_evaluation.csv"

    fieldnames = [
        "category",
        "file",
        "messages",
        "allowed",
        "blocked",
        "unknown",
        "errors",
        "block_reasons",
        "error_details"
    ]

    with report_path.open("w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print("\n=== Summary ===")
    print(f"Evaluated captures: {len(results)}")
    print(f"Benign captures: {capture_counts['benign']}")
    print(f"Attack captures: {capture_counts['attack']}")

    for category in ("benign", "attack"):
        category_results = [
            result for result in results
            if result["category"] == category
        ]

        messages = sum(r["messages"] for r in category_results)
        allowed = sum(r["allowed"] for r in category_results)
        blocked = sum(r["blocked"] for r in category_results)
        errors = sum(r["errors"] for r in category_results)

        print (f"\n{category.upper()}:")
        print(f" Modbus messages: {messages}")
        print(f" Allowed: {allowed}")
        print(f" Blocked: {blocked}")
        print(f" Captures with errors: {errors}")

    print(f"\nReport saved in {report_path.resolve()}")

if __name__ == "__main__":
    main()