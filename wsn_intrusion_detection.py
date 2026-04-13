# ============================================================
#   WSN INTRUSION DETECTION SYSTEM
#   Microproject - Cybersecurity & Network Infrastructure
#   CO Mapping: CO1, CO2, CO3
# ============================================================

import pandas as pd
import csv
import os
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from datetime import datetime
from collections import defaultdict

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
DATASET_FILE    = "wsn_packet_logs.csv"
OUTPUT_FILE     = "flagged_alerts.csv"
REPORT_FILE     = "detection_report.txt"
GRAPH_FILE      = "packet_rate_chart.png"

DOS_THRESHOLD   = 500     # packets per second threshold
AUTHORIZED_MACS = {
    "AA:BB:CC:DD:EE:01",
    "AA:BB:CC:DD:EE:02",
    "AA:BB:CC:DD:EE:03",
    "AA:BB:CC:DD:EE:04",
    "AA:BB:CC:DD:EE:05",
}

# ─────────────────────────────────────────────
# STEP 1: LOAD DATASET (File Handling)
# ─────────────────────────────────────────────
def load_dataset(filepath: str) -> list:
    """
    Reads the CSV packet log file using Python's built-in csv module.
    Returns a list of dictionaries (IoT database structure).
    CO1: Basic I/O and data structures
    """
    records = []
    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: {filepath}")
        return records

    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Convert datatypes
            row["packet_size"]       = int(row["packet_size"])
            row["transmission_rate"] = float(row["transmission_rate"])
            row["timestamp"]         = datetime.strptime(
                                          row["timestamp"], "%Y-%m-%d %H:%M:%S"
                                       )
            records.append(row)

    print(f"[INFO] Loaded {len(records)} packet records from '{filepath}'")
    return records


# ─────────────────────────────────────────────
# STEP 2: INTRUSION DETECTION ENGINE
#         (Control Structures - CO2)
# ─────────────────────────────────────────────
def detect_intrusions(records: list) -> list:
    """
    Applies rule-based detection using if/elif/else control structures:
      Rule 1 → DoS Attack: transmission_rate > DOS_THRESHOLD
      Rule 2 → Unauthorized MAC address
    Returns list of flagged alert dictionaries.
    CO2: Control structures, loops, conditions
    """
    alerts = []

    for record in records:
        flagged   = False
        alert_msg = ""

        # ── Rule 1: High Transmission Rate (DoS Detection) ──
        if record["transmission_rate"] > DOS_THRESHOLD:
            flagged   = True
            alert_msg = (
                f"DoS Attack Suspected — Transmission Rate: "
                f"{record['transmission_rate']} pkt/s "
                f"(threshold: {DOS_THRESHOLD} pkt/s)"
            )

        # ── Rule 2: Unauthorized MAC Address ──
        elif record["mac_address"] not in AUTHORIZED_MACS:
            flagged   = True
            alert_msg = (
                f"Unauthorized MAC Address: {record['mac_address']}"
            )

        # ── Normal Packet ──
        else:
            alert_msg = "Normal"

        if flagged:
            alerts.append({
                "timestamp"        : record["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                "node_id"          : record["node_id"],
                "mac_address"      : record["mac_address"],
                "packet_size"      : record["packet_size"],
                "transmission_rate": record["transmission_rate"],
                "protocol"         : record["protocol"],
                "alert"            : alert_msg
            })

    return alerts


# ─────────────────────────────────────────────
# STEP 3: SUMMARY STATISTICS
# ─────────────────────────────────────────────
def compute_summary(records: list, alerts: list) -> dict:
    """
    Computes summary counts for the final report.
    CO1: Variables, data types, arithmetic
    """
    total      = len(records)
    total_flag = len(alerts)
    normal     = total - total_flag

    dos_count = sum(1 for a in alerts if "DoS" in a["alert"])
    mac_count = sum(1 for a in alerts if "Unauthorized MAC" in a["alert"])

    node_counts = defaultdict(int)
    for a in alerts:
        node_counts[a["node_id"]] += 1

    return {
        "total"        : total,
        "normal"       : normal,
        "anomalous"    : total_flag,
        "dos_attacks"  : dos_count,
        "mac_violations": mac_count,
        "node_counts"  : dict(node_counts)
    }


# ─────────────────────────────────────────────
# STEP 4: SAVE ALERTS TO CSV (File Handling)
# ─────────────────────────────────────────────
def save_alerts(alerts: list, filepath: str):
    """
    Writes flagged alerts to a CSV output file.
    CO3: File handling — write mode
    """
    if not alerts:
        print("[INFO] No anomalies detected. No output file written.")
        return

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=alerts[0].keys())
        writer.writeheader()
        writer.writerows(alerts)

    print(f"[INFO] {len(alerts)} alerts saved to '{filepath}'")


# ─────────────────────────────────────────────
# STEP 5: SAVE TEXT REPORT (File Handling)
# ─────────────────────────────────────────────
def save_report(summary: dict, alerts: list, filepath: str):
    """
    Writes a human-readable detection report as a .txt file.
    CO3: File handling — text write mode
    """
    with open(filepath, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("   WSN INTRUSION DETECTION — SUMMARY REPORT\n")
        f.write(f"   Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"Total Packets Analysed : {summary['total']}\n")
        f.write(f"Normal Packets         : {summary['normal']}\n")
        f.write(f"Anomalous Packets      : {summary['anomalous']}\n")
        f.write(f"  ├─ DoS Attacks       : {summary['dos_attacks']}\n")
        f.write(f"  └─ MAC Violations    : {summary['mac_violations']}\n\n")

        f.write("Alerts Per Node:\n")
        for node, cnt in sorted(summary["node_counts"].items()):
            f.write(f"  {node} → {cnt} alert(s)\n")

        f.write("\n" + "-" * 60 + "\n")
        f.write("DETAILED ALERTS\n")
        f.write("-" * 60 + "\n")
        for i, a in enumerate(alerts, 1):
            f.write(
                f"\n[{i:03d}] {a['timestamp']} | {a['node_id']} | "
                f"MAC: {a['mac_address']}\n"
                f"      Rate: {a['transmission_rate']} pkt/s | "
                f"Size: {a['packet_size']} bytes | Proto: {a['protocol']}\n"
                f"      ⚠  {a['alert']}\n"
            )

    print(f"[INFO] Report saved to '{filepath}'")


# ─────────────────────────────────────────────
# STEP 6: GENERATE BAR CHART (matplotlib)
# ─────────────────────────────────────────────
def generate_chart(records: list, alerts: list, filepath: str):
    """
    Plots packet transmission rates per node.
    Anomalous nodes highlighted in RED, normal in GREEN.
    CO1/CO2: Data aggregation and visualization
    """
    df = pd.DataFrame(records)
    df["transmission_rate"] = df["transmission_rate"].astype(float)
    df["timestamp"] = df["timestamp"].apply(
        lambda x: x if isinstance(x, datetime) else datetime.strptime(x, "%Y-%m-%d %H:%M:%S")
    )

    # Average rate per node
    avg_rate = df.groupby("node_id")["transmission_rate"].mean().reset_index()
    avg_rate.columns = ["node_id", "avg_rate"]

    # Nodes with alerts
    alert_nodes = {a["node_id"] for a in alerts}

    colors = [
        "#E74C3C" if row["node_id"] in alert_nodes else "#2ECC71"
        for _, row in avg_rate.iterrows()
    ]

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle("WSN Intrusion Detection — Analysis Dashboard",
                 fontsize=14, fontweight="bold", y=1.01)

    # ── Chart 1: Avg Transmission Rate by Node ──
    bars = axes[0].bar(avg_rate["node_id"], avg_rate["avg_rate"],
                       color=colors, edgecolor="black", linewidth=0.7)
    axes[0].axhline(y=DOS_THRESHOLD, color="red", linestyle="--",
                    linewidth=1.5, label=f"DoS Threshold ({DOS_THRESHOLD} pkt/s)")
    axes[0].set_title("Average Transmission Rate per Node")
    axes[0].set_xlabel("Node ID")
    axes[0].set_ylabel("Avg Packets / Second")
    axes[0].legend()
    green_patch = mpatches.Patch(color="#2ECC71", label="Normal Node")
    red_patch   = mpatches.Patch(color="#E74C3C", label="Alert Node")
    axes[0].legend(handles=[green_patch, red_patch,
                             plt.Line2D([0], [0], color='red',
                                        linestyle='--', label=f'DoS Threshold ({DOS_THRESHOLD})')])

    for bar, val in zip(bars, avg_rate["avg_rate"]):
        axes[0].text(bar.get_x() + bar.get_width() / 2,
                     bar.get_height() + 2,
                     f"{val:.1f}", ha="center", va="bottom", fontsize=9)

    # ── Chart 2: Pie Chart — Normal vs Anomalous ──
    total      = len(records)
    anomalous  = len(alerts)
    normal_cnt = total - anomalous

    wedge_colors = ["#2ECC71", "#E74C3C"]
    axes[1].pie(
        [normal_cnt, anomalous],
        labels=[f"Normal\n({normal_cnt})", f"Anomalous\n({anomalous})"],
        colors=wedge_colors,
        autopct="%1.1f%%",
        startangle=90,
        explode=(0, 0.08),
        shadow=True,
        textprops={"fontsize": 11}
    )
    axes[1].set_title("Packet Classification — Normal vs Anomalous")

    plt.tight_layout()
    plt.savefig(filepath, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[INFO] Chart saved to '{filepath}'")


# ─────────────────────────────────────────────
# STEP 7: CONSOLE OUTPUT
# ─────────────────────────────────────────────
def print_console_report(summary: dict, alerts: list):
    """Prints a formatted summary to the terminal."""
    print()
    print("=" * 60)
    print("   WSN INTRUSION DETECTION SYSTEM — RESULTS")
    print("=" * 60)
    print(f"  Total Packets Analysed  : {summary['total']}")
    print(f"  Normal Packets          : {summary['normal']}")
    print(f"  Anomalous Packets       : {summary['anomalous']}")
    print(f"    ├─ DoS Attacks        : {summary['dos_attacks']}")
    print(f"    └─ MAC Violations     : {summary['mac_violations']}")
    print()
    print("  [ALERTS DETECTED]")
    print("-" * 60)
    for a in alerts:
        print(f"  ⚠  {a['timestamp']}  |  {a['node_id']}")
        print(f"      MAC     : {a['mac_address']}")
        print(f"      Rate    : {a['transmission_rate']} pkt/s")
        print(f"      Reason  : {a['alert']}")
        print()
    print("-" * 60)
    print(f"  Alerts saved  → {OUTPUT_FILE}")
    print(f"  Report saved  → {REPORT_FILE}")
    print(f"  Chart saved   → {GRAPH_FILE}")
    print("=" * 60)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print("\n[STARTING] WSN Intrusion Detection System...\n")

    # 1. Load dataset
    records = load_dataset(DATASET_FILE)
    if not records:
        return

    # 2. Detect intrusions
    alerts  = detect_intrusions(records)

    # 3. Compute summary
    summary = compute_summary(records, alerts)

    # 4. Save outputs
    save_alerts(alerts, OUTPUT_FILE)
    save_report(summary, alerts, REPORT_FILE)
    generate_chart(records, alerts, GRAPH_FILE)

    # 5. Console display
    print_console_report(summary, alerts)


if __name__ == "__main__":
    main()
