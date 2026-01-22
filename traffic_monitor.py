from scapy.all import sniff, IP, TCP, send
import time
import threading

class TrafficMonitor:
    def __init__(self):
        self.packet_count = 1

    def packet_callback(self, packet):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
        src_ip = dst_ip = src_port = dst_port = protocol = "N/A"

        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            if packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                protocol = "TCP"
            else:
                protocol = ip_layer.proto

        if protocol == "TCP" and src_ip == dst_ip and src_port > dst_port:
            return

        print(f"Packet {self.packet_count} -> Time: {timestamp}, Src: {src_ip}:{src_port}, Dst: {dst_ip}:{dst_port}, Protocol: {protocol}")
        self.packet_count += 1

    def wait_for_stop(self, stop_event):
        input("Press Enter to stop sniffing...\n")
        stop_event.set()
        # Send dummy packet to exit the blocking sniff call.
        dummy_pkt = IP(dst="127.0.0.1") / TCP(dport=12345, sport=54321, flags="S")
        send(dummy_pkt, verbose=0)

    def create_sniffer(self, filter_expr):
        stop_event = threading.Event()
        thread = threading.Thread(target=self.wait_for_stop, args=(stop_event,))
        thread.daemon = True
        thread.start()
        sniff(
            filter=filter_expr,
            store=False,
            prn=self.packet_callback,
            stop_filter=lambda pkt: stop_event.is_set()
        )

    def listen_incoming(self):
        print("Listening for inbound TCP packets...")
        self.create_sniffer("tcp and inbound")

    def listen_outgoing(self):
        print("Listening for outbound TCP packets...")
        self.create_sniffer("tcp and outbound")