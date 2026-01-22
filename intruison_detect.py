import time
from scapy.all import sniff, IP, TCP
import subprocess

class IntrusionDetector:
    PORT_THRESHOLD    = 6 
    TIME_WINDOW       = 150
    SEQUENTIAL_THRESH = 6
    OS_FP_THRESHOLD   = 5 
    OS_FP_TIME_WINDOW = 20

    def __init__(self):
        self.port_scan_history = {}
        self.os_fingerprint_history = {}

    def detect_anomaly(self, source_ip, ports_set, current_time):
        if len(ports_set) > self.PORT_THRESHOLD:
            timestamps = [t for t, _ in self.port_scan_history.get(source_ip, [])]
            time_span = int(current_time - min(timestamps)) if timestamps else 0
            timestamp_str = time.strftime("%y-%m-%d %H:%M:%S", time.localtime(current_time))
            targeted_ports = ", ".join(map(str, sorted(ports_set)))
            log_entry = f"{timestamp_str} —Multi Port Scanning — {source_ip} — {targeted_ports} — {time_span}s\n"
            with open("ids.log", "a") as log_file:
                log_file.write(log_entry)
            
            result = subprocess.run(
                ["sudo", "iptables", "-C", "INPUT", "-s", source_ip, "-j", "DROP"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            if result.returncode != 0:
                subprocess.run(
                    ["sudo", "iptables", "-I", "INPUT", "1", "-s", source_ip, "-j", "DROP"],
                    check=True
                )
            self.port_scan_history[source_ip] = []

    def detect_sequential(self, source_ip, ports_set, current_time):
        sorted_ports = sorted(ports_set)
       # print(ports_set)
        targeted_ports = set()
        targeted_ports.add(sorted_ports[0])
        if len(sorted_ports) >= self.SEQUENTIAL_THRESH:
            consecutive = 1
            attack = False 
            for i in range(1, len(sorted_ports)): 
                if sorted_ports[i] == sorted_ports[i-1] + 1:
                    consecutive += 1 
                    targeted_ports.add(sorted_ports[i]) 
                    if consecutive >= 6 : 
                        attack = True
                        break
                else:
                    consecutive = 1 
                    targeted_ports.clear()
                    targeted_ports.add(sorted_ports[i])
            # max_consecutive += 1
            if attack:
                print("Sequential scan detected with consecutive count:", consecutive)
                timestamps = [t for t, _ in self.port_scan_history.get(source_ip, [])]
                time_span = int(current_time - min(timestamps)) if timestamps else 0
                timestamp_str = time.strftime("%y-%m-%d %H:%M:%S", time.localtime(current_time)) 
                log_entry = f"{timestamp_str} — Sequential Port Scanning — {source_ip} — {targeted_ports} — {time_span}s\n"
                with open("ids.log", "a") as log_file:
                    log_file.write(log_entry)
                
                result = subprocess.run(
                    ["sudo", "iptables", "-C", "INPUT", "-s", source_ip, "-j", "DROP"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                if result.returncode != 0:
                    subprocess.run(
                        ["sudo", "iptables", "-I", "INPUT", "1", "-s", source_ip, "-j", "DROP"],
                        check=True
                    )
                self.port_scan_history[source_ip] = []

    def detect_os_fingerprint(self, source_ip, flags_set, current_time):
        if len(flags_set) >= self.OS_FP_THRESHOLD:
            timestamps = [t for t, _ in self.os_fingerprint_history.get(source_ip, [])]
            time_span = int(current_time - min(timestamps)) if timestamps else 0
            timestamp_str = time.strftime("%y-%m-%d %H:%M:%S", time.localtime(current_time))
            flagged = ", ".join(sorted(flags_set))
            log_entry = f"{timestamp_str} — OS Fingerprinting — {source_ip} — {flagged} — {time_span}s\n"
            with open("ids.log", "a") as log_file:
                log_file.write(log_entry)

            result = subprocess.run(
                ["sudo", "iptables", "-C", "INPUT", "-s", source_ip, "-j", "DROP"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            if result.returncode != 0:
                subprocess.run(
                    ["sudo", "iptables", "-I", "INPUT", "1", "-s", source_ip, "-j", "DROP"],
                    check=True
                )
            self.os_fingerprint_history[source_ip] = []

    def process_packet(self, packet):
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        ip_layer = packet.getlayer(IP)
        tcp_layer = packet.getlayer(TCP)
        source_ip = ip_layer.src
        dest_port = tcp_layer.dport
        current_time = time.time()

        if source_ip not in self.port_scan_history:
            self.port_scan_history[source_ip] = []
        self.port_scan_history[source_ip].append((current_time, dest_port))
        self.port_scan_history[source_ip] = [
            (t, port) for (t, port) in self.port_scan_history[source_ip]
            if current_time - t <= self.TIME_WINDOW
        ]
        ports_set = set(port for (t, port) in self.port_scan_history[source_ip])

        if source_ip not in self.os_fingerprint_history:
            self.os_fingerprint_history[source_ip] = []
        flag_combo = str(tcp_layer.flags)
        self.os_fingerprint_history[source_ip].append((current_time, flag_combo))
        self.os_fingerprint_history[source_ip] = [
            (t, flag) for (t, flag) in self.os_fingerprint_history[source_ip]
            if current_time - t <= self.OS_FP_TIME_WINDOW
        ]
        flags_set = set(flag for (t, flag) in self.os_fingerprint_history[source_ip])
        #print(ports_set)
        #self.detect_anomaly(source_ip, ports_set, current_time)
        self.detect_sequential(source_ip, ports_set, current_time)
        self.detect_os_fingerprint(source_ip, flags_set, current_time)

    def start_detection(self, stop_event):
        print("Starting anomaly-based port scanning detection...")
        try:
            sniff(
                filter="tcp and dst host 127.0.0.1",  # Correct filter
                store=False,
                prn=self.process_packet,
                stop_filter=lambda pkt: stop_event.is_set()
            )
        except KeyboardInterrupt:
            print("Detection stopped by user.")