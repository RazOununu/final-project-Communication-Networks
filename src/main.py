import os
import csv
import numpy as np
import pyshark
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


def parse_tls_header(tls_data):
    """
    Parses a TLS header given as a colon-separated hexadecimal string.
    Returns a tuple: (TLS Content Type, TLS Version, TLS Record Length).
    """
    hex_bytes = tls_data.split(':')
    if len(hex_bytes) < 5:
        return ("", "", "")
    content_type = hex_bytes[0]
    version = f"{hex_bytes[1]} {hex_bytes[2]}"
    record_length = int(f"{hex_bytes[3]}{hex_bytes[4]}", 16)
    content_types_map = {
        '14': 'Change Cipher Spec',
        '15': 'Alert',
        '16': 'Handshake',
        '17': 'Application Data'
    }
    versions_map = {
        '03 00': 'SSL 3.0',
        '03 01': 'TLS 1.0',
        '03 02': 'TLS 1.1',
        '03 03': 'TLS 1.2',
        '03 04': 'TLS 1.3'
    }
    tls_content_type = content_types_map.get(content_type, content_type)
    tls_version = versions_map.get(version, version)
    return (tls_content_type, tls_version, record_length)


def parse_tcp_flags(hex_flags):
    """
    Converts hexadecimal TCP flags into a descriptive string.
    """
    tcp_flags_map = {
        '0x0000': 'No Flags',
        '0x0001': 'FIN',
        '0x0002': 'SYN',
        '0x0003': 'FIN+SYN',
        '0x0004': 'RST',
        '0x0005': 'RST+FIN',
        '0x0008': 'PSH',
        '0x0009': 'FIN+PSH',
        '0x000A': 'SYN+PSH',
        '0x000C': 'RST+PSH',
        '0x0010': 'ACK',
        '0x0011': 'FIN+ACK',
        '0x0012': 'SYN+ACK',
        '0x0014': 'RST+ACK',
        '0x0018': 'PSH+ACK'
    }
    return tcp_flags_map.get(hex_flags, hex_flags)



def process_pcap_file(pcap_file, tls_keys_file=None):
    """
    Processes a single PCAP file and extracts the following fields for each packet:
      - Timestamp, Packet Length, Src IP, Dst IP, TTL, IP Version,
      - Protocol (filtered: TCP, DNS, UDP, QUIC, PLS, HTTP2, HTTP3, HTTP; else "Other"),
      - Src Port, Dst Port, TCP Flags, TCP Window Size,
      - TLS Version, TLS Content Type, TLS Record Length,
      - Flow Hash, Packet Inter-arrival Time.
    Uses the provided TLS keys file if available.
    Returns a list of dictionaries (one per packet).
    """
    rows = []
    override_prefs = {}
    if tls_keys_file and os.path.isfile(tls_keys_file):
        override_prefs['tls.keylog_file'] = tls_keys_file

    # Set of  protocols
    protocols = {"TCP", "DNS", "UDP", "QUIC", "TLS", "HTTP2", "HTTP3", "HTTP"}

    try:
        capture = pyshark.FileCapture(
            pcap_file, use_json=True, override_prefs=override_prefs,
            display_filter="ip or ipv6 or tcp or udp or tls or quic or dns or http"
        )
        previous_timestamp = None

        for packet in capture:
            row = {}
            # Timestamp and Packet Inter-arrival Time
            timestamp = float(packet.sniff_timestamp)
            row["Timestamp"] = timestamp
            if previous_timestamp is None:
                inter_arrival = 0.0
            else:
                inter_arrival = timestamp - previous_timestamp
            row["Packet Inter-arrival Time"] = inter_arrival
            previous_timestamp = timestamp

            # Packet Length
            row["Packet Length"] = packet.length if hasattr(packet, "length") else ""

            # IP Header Fields: Src IP, Dst IP, TTL, and IP Version
            if hasattr(packet, "ip"):
                row["Src IP"] = packet.ip.src
                row["Dst IP"] = packet.ip.dst
                row["TTL"] = packet.ip.ttl
                row["IP Version"] = "IPv4"
                ip_version = "IPv4"
            elif hasattr(packet, "ipv6"):
                row["Src IP"] = packet.ipv6.src
                row["Dst IP"] = packet.ipv6.dst
                row["TTL"] = packet.ipv6.hlim
                row["IP Version"] = "IPv6"
                ip_version = "IPv6"
            else:
                row["Src IP"] = ""
                row["Dst IP"] = ""
                row["TTL"] = ""
                row["IP Version"] = ""
                ip_version = ""

            # Protocol
            proto = packet.highest_layer.upper() if hasattr(packet, "highest_layer") else ""
            if proto in protocols:
                row["Protocol"] = proto
            else:
                row["Protocol"] = "Other"


            row["Src Port"] = ""
            row["Dst Port"] = ""
            row["TCP Flags"] = ""
            row["TCP Window Size"] = ""
            if hasattr(packet, "tcp"):
                if hasattr(packet.tcp, "srcport"):
                    row["Src Port"] = packet.tcp.srcport
                if hasattr(packet.tcp, "dstport"):
                    row["Dst Port"] = packet.tcp.dstport
                if hasattr(packet.tcp, "flags"):
                    row["TCP Flags"] = parse_tcp_flags(packet.tcp.flags)
                if hasattr(packet.tcp, "window_size_value"):
                    row["TCP Window Size"] = packet.tcp.window_size_value
            elif hasattr(packet, "udp"):
                if hasattr(packet.udp, "srcport"):
                    row["Src Port"] = packet.udp.srcport
                if hasattr(packet.udp, "dstport"):
                    row["Dst Port"] = packet.udp.dstport

            # TLS Header Fields
            row["TLS Version"] = ""
            row["TLS Content Type"] = ""
            row["TLS Record Length"] = ""
            if hasattr(packet, "tls"):
                if hasattr(packet.tls, "data"):
                    tls_data = packet.tls.data
                    try:
                        tls_content_type, tls_version, record_length = parse_tls_header(tls_data)
                        row["TLS Content Type"] = tls_content_type
                        row["TLS Version"] = tls_version
                        row["TLS Record Length"] = record_length
                    except Exception:
                        pass
                else:
                    if hasattr(packet.tls, "record_version"):
                        row["TLS Version"] = packet.tls.record_version
                    if hasattr(packet.tls, "record_length"):
                        row["TLS Record Length"] = packet.tls.record_length

            # Flow Hash computed from (IP version, Src IP, Dst IP, Src Port, Dst Port, Protocol)
            flow_tuple = (ip_version, row["Src IP"], row["Dst IP"], row["Src Port"], row["Dst Port"], row["Protocol"])
            row["Flow Hash"] = hash(flow_tuple)

            rows.append(row)
        capture.close()
    except Exception as e:
        print(f"Error processing file {pcap_file}: {e}")
    return rows



def write_csv_for_pcap(rows, output_csv):
    if not rows:
        print("No data extracted to write CSV.")
        return
    fieldnames = [
        "Timestamp", "Packet Length", "Src IP", "Dst IP","IP Version", "TTL", "Protocol",
        "Src Port", "Dst Port", "TCP Flags", "TCP Window Size",
        "TLS Version", "TLS Content Type", "TLS Record Length",
        "Flow Hash", "Packet Inter-arrival Time"
    ]
    with open(output_csv, mode="w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"CSV created: {output_csv}")


def process_all_pcaps(captures_folder, logs_folder, output_dir):
    pcap_files = [os.path.join(captures_folder, f) for f in os.listdir(captures_folder) if f.endswith(".pcapng")]
    for pcap_file in pcap_files:
        print(f"Processing file: {pcap_file}")
        base_name = os.path.splitext(os.path.basename(pcap_file))[0]
        tls_key_file = os.path.join(logs_folder, base_name + ".log")
        if not os.path.isfile(tls_key_file):
            print(f"TLS key file not found for {base_name}. Proceeding without TLS keys.")
            tls_key_file = None
        rows = process_pcap_file(pcap_file, tls_key_file)
        output_csv = os.path.join(output_dir, base_name + ".csv")
        write_csv_for_pcap(rows, output_csv)


def plot_ttl_distribution(output_dir):
    """
    Reads all CSV files in output_dir, aggregates TTL counts into defined bins,
    and plots a grouped bar chart.

    For each TTL bin, the chart displays a bar per application (CSV) in a different color,
    allowing comparison of TTL distributions between applications.
    """

    csv_files = [os.path.join(output_dir, f) for f in os.listdir(output_dir) if f.endswith(".csv")]
    if not csv_files:
        print("No CSV files found in output directory.")
        return

    bins = [0,56,65,120,129,246,256]
    bin_labels = ["0-55","56-64","65-119", "120-128", "129-245","246-255"]

    app_counts = {}
    for csv_file in csv_files:
        app_name = os.path.splitext(os.path.basename(csv_file))[0]
        df = pd.read_csv(csv_file)
        ttl_values = pd.to_numeric(df["TTL"], errors="coerce").dropna()
        counts, _ = np.histogram(ttl_values, bins=bins)
        app_counts[app_name] = counts

    apps = list(app_counts.keys())
    num_apps = len(apps)
    num_bins = len(bin_labels)
    x = np.arange(num_bins)
    bar_width = 0.8 / num_apps

    plt.figure(figsize=(12, 6))
    for i, app in enumerate(apps):
        counts = app_counts[app]

        plt.bar(x + i * bar_width, counts, width=bar_width, label=app)

    plt.xlabel("TTL Bins")
    plt.ylabel("Number of Packets")
    plt.title("TTL Distribution")

    plt.xticks(x + bar_width * (num_apps - 1) / 2, bin_labels)
    plt.legend(title="Application")
    plt.tight_layout()

    output_path = os.path.join(output_dir, "ttl_distribution.png")
    plt.savefig(output_path)
    plt.close()
    print(f"Grouped TTL distribution graph saved as: {output_path}")


def plot_avg_inter_arrival_times(output_dir):
    csv_files = [os.path.join(output_dir, f) for f in os.listdir(output_dir) if f.endswith(".csv")]
    avg_times = {}
    for csv_file in csv_files:
        df = pd.read_csv(csv_file)
        app_name = os.path.splitext(os.path.basename(csv_file))[0]
        if "Packet Inter-arrival Time" in df.columns:
            inter_arrival_times = pd.to_numeric(df["Packet Inter-arrival Time"], errors="coerce").dropna()
            if not inter_arrival_times.empty:
                avg_times[app_name] = inter_arrival_times.mean()
    avg_df = pd.DataFrame(list(avg_times.items()), columns=["Application", "Avg Inter-arrival Time"])
    plt.figure(figsize=(10, 6))
    sns.barplot(x="Application", y="Avg Inter-arrival Time", data=avg_df, hue='Application', palette='Set2')
    plt.title("Average Packet Inter-arrival Time Across Applications")
    plt.xlabel("Application")
    plt.ylabel("Avg Inter-arrival Time (ms)")
    output_path = os.path.join(output_dir, 'avg_inter_arrival_time.png')
    plt.savefig(output_path)
    plt.close()
    print(f"Average Inter-arrival Time graph saved as: {output_path}")


def plot_tcp_flags_distribution(output_dir):
    csv_files = [os.path.join(output_dir, f) for f in os.listdir(output_dir) if f.endswith(".csv")]
    data = []

    for csv_file in csv_files:
        df = pd.read_csv(csv_file)
        app_name = os.path.splitext(os.path.basename(csv_file))[0]
        flags_count = df['TCP Flags'].value_counts().to_dict()
        flags_count['Application'] = app_name
        data.append(flags_count)
    combined_data = pd.DataFrame(data).fillna(0)
    combined_data.set_index('Application', inplace=True)
    pastel_colors = sns.color_palette("pastel", len(combined_data.columns))
    plt.figure(figsize=(14, 8))
    ax = combined_data.plot(kind='bar', width=0.8, color=pastel_colors, figsize=(14, 8))
    plt.title('TCP Flags Distribution Across Applications', fontsize=16, fontweight='bold')
    plt.xlabel('Application', fontsize=14)
    plt.ylabel('Number of Flags', fontsize=14)
    plt.xticks(rotation=45, ha='right', fontsize=12)
    plt.yticks(fontsize=12)
    for container in ax.containers:
        ax.bar_label(container, fmt='%d', fontsize=10, padding=3)
    plt.legend(title='TCP Flag', fontsize=12, title_fontsize=14, loc='upper right')
    output_path = os.path.join(output_dir, 'tcp_flags_grouped_distribution.png')
    plt.savefig(output_path, bbox_inches='tight', dpi=300)
    plt.close()

    print(f"TCP flags distribution graph saved as: {output_path}")

def plot_window_size_over_time(output_dir):
    csv_files = [os.path.join(output_dir, f) for f in os.listdir(output_dir) if f.endswith(".csv")]
    data = []
    for csv_file in csv_files:
        df = pd.read_csv(csv_file)
        app_name = os.path.splitext(os.path.basename(csv_file))[0]
        df['Application'] = app_name
        df = df[['Application', 'TCP Window Size']].dropna().copy()
        data.append(df)
    combined_data = pd.concat(data, ignore_index=True)
    plt.figure(figsize=(14, 8))
    for app in combined_data['Application'].unique():
        subset = combined_data[combined_data['Application'] == app].copy()
        subset.loc[:, 'Smoothed'] = subset['TCP Window Size'].rolling(window=50).mean()
        plt.plot(subset.index, subset['Smoothed'], label=app, alpha=0.7, linewidth=0.8)
    plt.ylim(0, 30000)
    yticks = np.linspace(0, 30000, num=10, dtype=int)
    plt.yticks(yticks)
    plt.title('Smoothed Window Size Over Time by Application')
    plt.xlabel('Packet Number')
    plt.ylabel('Window Size (Bytes)')
    plt.legend(title='Application')
    output_path = os.path.join(output_dir, 'window_size_over_time.png')
    plt.savefig(output_path, bbox_inches='tight', dpi=300)
    plt.close()
    print(f"Window size over time graph saved as: {output_path}")


def plot_tls_headers(output_dir):
    csv_files = [os.path.join(output_dir, f) for f in os.listdir(output_dir) if f.endswith(".csv")]
    data = []
    for csv_file in csv_files:
        df = pd.read_csv(csv_file)
        app_name = os.path.splitext(os.path.basename(csv_file))[0]
        df['Application'] = app_name
        df = df[['Application', 'TLS Content Type', 'TLS Record Length']].dropna()
        data.append(df)
    tls_data = pd.concat(data, ignore_index=True)
    tls_data['TLS Content Type'] = tls_data['TLS Content Type'].astype('category').cat.codes
    plt.figure(figsize=(12, 6))
    sns.scatterplot(data=tls_data, x='TLS Record Length', y='TLS Content Type', hue='Application', alpha=0.7)
    plt.title('TLS Record Length vs. TLS Content Type by Application')
    plt.xlabel('TLS Record Length (Bytes)')
    plt.ylabel('TLS Content Type (Encoded)')
    plt.legend(title='Application')
    output_path = os.path.join(output_dir, 'plot_tls_headrs.png')
    plt.savefig(output_path)
    plt.close()
    print(f"TLS scatter plot saved as: {output_path}")


def plot_flow_volume(output_dir):
    csv_files = [os.path.join(output_dir, f) for f in os.listdir(output_dir) if f.endswith(".csv")]
    data = []
    for csv_file in csv_files:
        df = pd.read_csv(csv_file)
        app_name = os.path.splitext(os.path.basename(csv_file))[0]
        df['Application'] = app_name
        total_flow_volume = df['Packet Length'].sum()
        data.append({'Application': app_name, 'Flow Volume': total_flow_volume})
    volume_df = pd.DataFrame(data)
    plt.figure(figsize=(12, 6))
    sns.barplot(data=volume_df, x='Application', y='Flow Volume', hue='Application', palette='pastel')
    plt.title("Flow Volume per Application", fontsize=16, fontweight='bold')
    plt.xlabel("Application", fontsize=14)
    plt.ylabel("Total Flow Volume (Bytes)", fontsize=14)
    plt.xticks(rotation=45, ha='right', fontsize=12)
    for index, row in volume_df.iterrows():
        plt.text(index, row['Flow Volume'], f"{row['Flow Volume']:,}", ha='center', va='bottom', fontsize=10)
    output_path = os.path.join(output_dir, "plot_flow_volume.png")
    plt.savefig(output_path, bbox_inches='tight', dpi=300)
    plt.close()
    print(f"Flow volume bar graph saved as: {output_path}")


def plot_protocol_distribution(output_dir):
    """
    Reads all CSV files in output_dir, counts how many packets belong to each 'Protocol'
    (only TCP, TLS, UDP), and plots a grouped bar chart where each CSV (application)
    is shown as a separate group.

    Even if a protocol is not present in a particular CSV, it will appear with a 0 bar.
    """

    # CSV
    csv_files = [os.path.join(output_dir, f) for f in os.listdir(output_dir) if f.endswith(".csv")]
    if not csv_files:
        print("No CSV files found in output directory.")
        return

    allowed_protocols = ["TCP", "TLS", "UDP"]  #  fixe

    app_protocol_counts = {}

    for csv_file in csv_files:
        app_name = os.path.splitext(os.path.basename(csv_file))[0]
        df = pd.read_csv(csv_file)

        protocol_counts = {proto: 0 for proto in allowed_protocols}

        if "Protocol" in df.columns:
            for proto in df["Protocol"].dropna():
                if proto in protocol_counts:
                    protocol_counts[proto] += 1

        app_protocol_counts[app_name] = protocol_counts

    apps = list(app_protocol_counts.keys())
    num_apps = len(apps)

    x = np.arange(len(allowed_protocols))  # 3 protocoles
    bar_width = 0.8 / num_apps

    plt.figure(figsize=(12, 6))

    for i, app in enumerate(apps):
        counts = [app_protocol_counts[app][proto] for proto in allowed_protocols]
        plt.bar(x + i * bar_width, counts, width=bar_width, label=app)

    plt.xticks(x + bar_width * (num_apps - 1) / 2, allowed_protocols, rotation=45)
    plt.xlabel("Protocol")
    plt.ylabel("Number of Packets")
    plt.title("Protocol Distribution (TCP, TLS, UDP)")
    plt.legend(title="Application")
    plt.tight_layout()

    output_path = os.path.join(output_dir, "protocol_distribution.png")
    plt.savefig(output_path)
    plt.close()
    print(f"Protocol distribution graph saved as: {output_path}")

def plot_packet_length_distribution(output_dir):
    csv_files = [os.path.join(output_dir, f) for f in os.listdir(output_dir) if f.endswith(".csv")]
    data = []

    for csv_file in csv_files:
        df = pd.read_csv(csv_file)
        app_name = os.path.splitext(os.path.basename(csv_file))[0]
        df['Application'] = app_name
        df = df[['Application', 'Packet Length']].dropna()
        data.append(df)

    combined_data = pd.concat(data, ignore_index=True)

    plt.figure(figsize=(12, 8))

    for app in combined_data['Application'].unique():
        subset = combined_data[combined_data['Application'] == app]
        sns.kdeplot(subset['Packet Length'], label=app, fill=True)

    plt.title('Continuous Packet Length Distribution Across Applications')
    plt.xlabel('Packet Length (Bytes)')
    plt.ylabel('Density')
    plt.legend()

    output_path = os.path.join(output_dir, 'packet_length_distribution.png')
    plt.savefig(output_path)
    plt.close()
    print(f"Packet length distribution graph saved as: {output_path}")

def plot_packet_size_distribution(output_dir):

    csv_files = [os.path.join(output_dir, f) for f in os.listdir(output_dir) if f.endswith(".csv")]
    if not csv_files:
        print("No CSV files found in output directory.")
        return

    bins = [0, 200, 400, 600, 800, 1000, 1200, 1500, 2000, 3000, 9999999]
    bin_labels = ["0-200", "200-400", "400-600", "600-800", "800-1000",
                  "1000-1200", "1200-1500", "1500-2000", "2000-3000", "3000+"]

    app_counts = {}

    for csv_file in csv_files:
        app_name = os.path.splitext(os.path.basename(csv_file))[0]
        df = pd.read_csv(csv_file)

        pkt_length = pd.to_numeric(df["Packet Length"], errors="coerce").dropna()

        counts, _ = np.histogram(pkt_length, bins=bins)
        app_counts[app_name] = counts

    apps = list(app_counts.keys())
    num_apps = len(apps)
    num_bins = len(bin_labels)

    x = np.arange(num_bins)
    bar_width = 0.8 / num_apps

    plt.figure(figsize=(12, 6))

    for i, app in enumerate(apps):
        counts = app_counts[app]

        plt.bar(x + i * bar_width, counts, width=bar_width, label=app)

    plt.xlabel("Packet Length Bins (Bytes)")
    plt.ylabel("Number of Packets")
    plt.title("Packet Length Distribution")

    plt.xticks(x + bar_width * (num_apps - 1) / 2, bin_labels, rotation=45)
    plt.legend(title="Application")
    plt.tight_layout()

    output_path = os.path.join(output_dir, "packet_size_distribution.png")
    plt.savefig(output_path)
    plt.close()
    print(f"Grouped packet size distribution graph saved as: {output_path}")







if __name__ == "__main__":
    CAPTURES_FOLDER = "captures"
    LOGS_FOLDER = "logs"
    OUTPUT_DIR = "output"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    process_all_pcaps(CAPTURES_FOLDER, LOGS_FOLDER, OUTPUT_DIR)
    plot_ttl_distribution(OUTPUT_DIR)
    plot_packet_size_distribution(OUTPUT_DIR)
    plot_packet_length_distribution(OUTPUT_DIR)
    plot_avg_inter_arrival_times(OUTPUT_DIR)
    plot_tcp_flags_distribution(OUTPUT_DIR)
    plot_window_size_over_time(OUTPUT_DIR)
    plot_tls_headers(OUTPUT_DIR)
    plot_flow_volume(OUTPUT_DIR)
    plot_protocol_distribution(OUTPUT_DIR)

    print(f"success! all graphs are located in the output directory :)")


