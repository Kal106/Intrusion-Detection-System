import subprocess
from scapy.all import IP, TCP
import random
import time

DEFAULT_SRC_IP = "127.0.0.1"

def generate_normal_traffic():
    # Normal traffic: ACK and PSH flags; using modified source IP
    pkt = IP(src=DEFAULT_SRC_IP, dst="127.0.0.1") / TCP(sport=12345, dport=80, flags="AP")
    return pkt

def generate_syn_flood(target_port, count=5):
    # SYN flood attack: multiple SYN packets to same target port
    packets = []
    for i in range(count):
        pkt = IP(src=DEFAULT_SRC_IP, dst="127.0.0.1") / TCP(sport=1024+i, dport=target_port, flags="S")
        packets.append(pkt)
    return packets

def generate_port_scan(start_port, end_port):
    # Port scan: multiple SYN packets from a fixed source port to different destination ports
    packets = []
    source_port = 40000  # fixed source port
    for dport in range(start_port, end_port+1):
        pkt = IP(src=DEFAULT_SRC_IP, dst="127.0.0.1") / TCP(sport=source_port, dport=dport, flags="S")
        packets.append(pkt)
    return packets

def generate_hping3_attack(packets, choice):
    # Use hping3 to transmit all the packets in the provided list.
    print("Packets Size ", len(packets))
    c = 0
    for pkt in packets:
        if choice == "3" or choice == "1":
            time.sleep(3)
        c += 1
        ip_layer = pkt.getlayer(IP)
        tcp_layer = pkt.getlayer(TCP)
        if not (ip_layer and tcp_layer):
            continue
        
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        sport = tcp_layer.sport
        dport = tcp_layer.dport
        flags = str(tcp_layer.flags)

        # Base hping3 command: send one packet from src to dst with specified ports.
        command = ["sudo", "hping3", "-c", "1", "-a", src_ip, "-s", str(sport), "-p", str(dport)]

        flag_mapping = {
            'S': "-S",
            'A': "-A",
            'P': "-P",
            'F': "-F",
            'R': "-R",
            'U': "-U"
        }
        for flag in flags:
            if flag in flag_mapping:
                command.append(flag_mapping[flag])
        
        command.append(dst_ip)

        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            print(f"{c}. Packet: IP {src_ip} : {sport} -> {dst_ip} : {dport} | Flags: {tcp_layer.flags}")
        except subprocess.CalledProcessError as e:
            print("Error running hping3 attack for packet:", e.stderr)
        

def analyze_packet(pkt):
    ip_layer = pkt.getlayer(IP)
    tcp_layer = pkt.getlayer(TCP)
    
    src_ip = ip_layer.src if ip_layer else "N/A"
    dst_ip = ip_layer.dst if ip_layer else "N/A"
    sport = tcp_layer.sport if tcp_layer else "N/A"
    dport = tcp_layer.dport if tcp_layer else "N/A"
    flags = tcp_layer.flags if tcp_layer else "N/A"
    protocol = "TCP" if tcp_layer else "Unknown"
    
    print(f"Analyse: Packet -> Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {sport}, Destination Port: {dport}, Protocol: {protocol}, Flags: {flags}")

def main():
    while True:
        print("\nSelect the type of packets to generate:")
        print("1. Normal Traffic")
        print("2. Multiple Port Attack")
        print("3. Sequential Port Scan Attack")
        print("4. SYN/ACK/FIN Flood Attack")
        print("5. Exit")

        choice = input("Enter your choice (1/2/3/4): ").strip()
        if choice > '5':
            print("Invalid choice. Please try again.")
            continue
        elif choice == "5":
            print("Exiting.")
            break

        packets = []
        
        src_port = int(input("Attacker Port: "))
        
        if choice == "1":
            count = int(input("Enter the number of normal packets to generate: ").strip())
            for _ in range(count):
                dst_port = random.randint(1024, 65535)
                pkt = IP(src=DEFAULT_SRC_IP, dst="127.0.0.1") / TCP(sport=src_port, dport=dst_port, flags="AP")
                packets.append(pkt)
    
        elif choice == "2":
            num_requests = int(input("Enter the number of ports to scan: ").strip())
            # start_port = int(input("Enter the starting port for Port Scan: ").strip())
            for i in range(num_requests):
                dport = random.randint(1024, 65535)
                packets.append(IP(src=DEFAULT_SRC_IP, dst="127.0.0.1") / TCP(sport=src_port, dport=dport, flags="S"))

        elif choice == "3":
            num_requests = int(input("Enter the number of ports to scan: ").strip())
            start_port = int(input("Enter the starting port for Port Scan: ").strip())
            for i in range(num_requests):
                dport = start_port + i
                packets.append(IP(src=DEFAULT_SRC_IP, dst="127.0.0.1") / TCP(sport=src_port, dport=dport, flags="S"))
        
        elif choice == "4":
            unique_combinations = set()        
            total_pack = int(input("Enter the number of random mix Packets: ").strip())
            flag_options = ["S", "A", "F", "SA", "SF", "AF", "SAF", "P", "AP"]
            for _ in range(total_pack):
                dport = 9010
                flag = random.choice(flag_options)
                packets.append(IP(src=DEFAULT_SRC_IP, dst="127.0.0.1") / TCP(sport=src_port, dport=dport, flags=flag))
                unique_combinations.add(flag)
            
        # print("\nExecuting hping3 based test attack:")
        # print(packets)
        generate_hping3_attack(packets, choice)

if __name__ == "__main__":
    main()
