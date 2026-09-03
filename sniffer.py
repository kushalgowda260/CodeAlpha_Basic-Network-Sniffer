from scapy.all import sniff
from datetime import datetime


# =========================================================
# BASIC NETWORK SNIFFER
# CodeAlpha Cyber Security Internship - Task 1
# =========================================================


# -------------------------
# COMMON SERVICES
# -------------------------

SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}


# -------------------------
# PACKET STATISTICS
# -------------------------

tcp_count = 0
udp_count = 0
icmp_count = 0
other_count = 0
total_count = 0


# -------------------------
# PORT ACTIVITY
# -------------------------

port_activity = {}

# Keep track of IPs that have already generated an alert
alerted_ips = set()


# -------------------------
# LOGGING FUNCTION
# -------------------------

def save_to_log(
    source,
    destination,
    protocol,
    source_port,
    destination_port,
    service
):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with open("network_log.txt", "a") as file:

        file.write(
            f"Time: {timestamp}\n"
        )

        file.write(
            f"Source: {source}\n"
        )

        file.write(
            f"Destination: {destination}\n"
        )

        file.write(
            f"Protocol: {protocol}\n"
        )

        file.write(
            f"Source Port: {source_port}\n"
        )

        file.write(
            f"Destination Port: {destination_port}\n"
        )

        file.write(
            f"Service: {service}\n"
        )

        file.write(
            "-" * 50 + "\n"
        )


# -------------------------
# SECURITY ALERT LOG
# -------------------------

def save_alert_to_log(source, port_count):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with open("security_alerts.txt", "a") as file:

        file.write(
            f"Time: {timestamp}\n"
        )

        file.write(
            "Alert: Possible Port Scan\n"
        )

        file.write(
            f"Source IP: {source}\n"
        )

        file.write(
            f"Different Ports: {port_count}\n"
        )

        file.write(
            "-" * 50 + "\n"
        )


# -------------------------
# PACKET CALLBACK
# -------------------------

def packet_callback(packet):

    global tcp_count
    global udp_count
    global icmp_count
    global other_count
    global total_count

    # Count packet
    total_count += 1

    source = "Unknown"
    destination = "Unknown"

    protocol = "Unknown"

    source_port = "N/A"
    destination_port = "N/A"

    service = "N/A"


    # =====================================================
    # IP ADDRESS DETECTION
    # =====================================================

    # IPv4
    if packet.haslayer("IP"):

        source = packet["IP"].src
        destination = packet["IP"].dst


    # IPv6
    elif packet.haslayer("IPv6"):

        source = packet["IPv6"].src
        destination = packet["IPv6"].dst


    # =====================================================
    # PROTOCOL DETECTION
    # =====================================================

    # TCP
    if packet.haslayer("TCP"):

        protocol = "TCP"

        tcp_count += 1

        source_port = packet["TCP"].sport
        destination_port = packet["TCP"].dport


    # UDP
    elif packet.haslayer("UDP"):

        protocol = "UDP"

        udp_count += 1

        source_port = packet["UDP"].sport
        destination_port = packet["UDP"].dport


    # ICMPv4
    elif packet.haslayer("ICMP"):

        protocol = "ICMPv4"

        icmp_count += 1


    # ICMPv6
    elif packet.haslayer("ICMPv6"):

        protocol = "ICMPv6"

        icmp_count += 1


    # Other traffic
    else:

        other_count += 1


    # =====================================================
    # SERVICE IDENTIFICATION
    # =====================================================

    if destination_port != "N/A":

        service = SERVICES.get(
            destination_port,
            "Unknown"
        )


    # =====================================================
    # PORT ACTIVITY TRACKING
    # =====================================================

    if source not in port_activity:

        port_activity[source] = set()


    if destination_port != "N/A":

        port_activity[source].add(
            destination_port
        )


    # =====================================================
    # BASIC PORT SCAN DETECTION
    # =====================================================

    port_count = len(
        port_activity[source]
    )


    # Alert after 10 different ports
    if port_count >= 10:

        if source not in alerted_ips:

            print()
            print("!" * 55)
            print("⚠️  SECURITY ALERT")
            print("Possible Port Scan Detected")
            print("Source IP:", source)
            print(
                "Different Ports:",
                port_count
            )
            print("!" * 55)
            print()

            save_alert_to_log(
                source,
                port_count
            )

            alerted_ips.add(source)


    # =====================================================
    # SAVE PACKET
    # =====================================================

    save_to_log(
        source,
        destination,
        protocol,
        source_port,
        destination_port,
        service
    )


    # =====================================================
    # DISPLAY PACKET
    # =====================================================

    print("=" * 55)

    print("PACKET")

    print("=" * 55)

    print(
        "Source IP       :",
        source
    )

    print(
        "Destination IP  :",
        destination
    )

    print(
        "Protocol        :",
        protocol
    )

    print(
        "Source Port     :",
        source_port
    )

    print(
        "Destination Port:",
        destination_port
    )

    print(
        "Service         :",
        service
    )

    print("=" * 55)


# =========================================================
# FILTER MENU
# =========================================================

print()
print("=" * 55)
print("          BASIC NETWORK SNIFFER")
print("=" * 55)

print()
print("Choose packet filter:")
print()
print("1. TCP")
print("2. UDP")
print("3. ICMP")
print("4. All")
print()

choice = input(
    "Enter your choice: "
)


# =========================================================
# START PACKET CAPTURE
# =========================================================

try:

    if choice == "1":

        print()
        print("Capturing TCP packets...")
        print("Press Ctrl+C to stop.")
        print()

        sniff(
            filter="tcp",
            prn=packet_callback
        )


    elif choice == "2":

        print()
        print("Capturing UDP packets...")
        print("Press Ctrl+C to stop.")
        print()

        sniff(
            filter="udp",
            prn=packet_callback
        )


    elif choice == "3":

        print()
        print("Capturing ICMP packets...")
        print("Press Ctrl+C to stop.")
        print()

        sniff(
            filter="icmp or icmp6",
            prn=packet_callback
        )


    elif choice == "4":

        print()
        print("Capturing all packets...")
        print("Press Ctrl+C to stop.")
        print()

        sniff(
            prn=packet_callback
        )


    else:

        print()
        print("Invalid choice.")
        print("Please run the program again.")


# =========================================================
# STOP SNIFFER
# =========================================================

except KeyboardInterrupt:

    print()
    print()
    print("=" * 55)
    print("             PACKET STATISTICS")
    print("=" * 55)

    print(
        "TCP packets   :",
        tcp_count
    )

    print(
        "UDP packets   :",
        udp_count
    )

    print(
        "ICMP packets  :",
        icmp_count
    )

    print(
        "Other packets :",
        other_count
    )

    print(
        "Total packets :",
        total_count
    )

    print("=" * 55)


    # -------------------------
    # PORT ACTIVITY SUMMARY
    # -------------------------

    print()
    print("PORT ACTIVITY")
    print("=" * 55)

    for ip, ports in port_activity.items():

        if ports:

            print(
                ip,
                "->",
                sorted(ports)
            )


    print()
    print("=" * 55)
    print("Logs:")
    print("network_log.txt")
    print("security_alerts.txt")
    print("=" * 55)

    print()
    print("Sniffer stopped.")