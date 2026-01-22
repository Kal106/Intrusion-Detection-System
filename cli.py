import os
import sys
import pyfiglet
import threading
import time
import subprocess
from colorama import Fore, init
from traffic_monitor import TrafficMonitor
from intruison_detect import IntrusionDetector

init(autoreset=True)

class IDSCLI:
    def __init__(self):
        self.detector = IntrusionDetector()
        self.ids_thread = None
        self.ids_stop_event = threading.Event()
        self.traffic_monitor = TrafficMonitor()

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_menu(self):
        self.clear_screen()
        title = pyfiglet.figlet_format("NIDPS")
        print(Fore.CYAN + title)
        print(Fore.YELLOW + "=" * 50)
        print(Fore.GREEN + "1. Start/Stop IDS")
        print(Fore.GREEN + "2. View Live Traffic")
        print(Fore.GREEN + "3. View Intrusion Logs")
        print(Fore.GREEN + "4. Display Blocked IPs")
        print(Fore.GREEN + "5. Clear Block List")
        print(Fore.GREEN + "6. Unblock an IP")
        print(Fore.RED + "7. Exit")
        print(Fore.YELLOW + "=" * 50)

    def start_ids(self):
        print(Fore.BLUE + "\nNIDPS is now running!")
        self.detector.start_detection(self.ids_stop_event)
        print(Fore.RED + "\nNIDPS stopped.")

    def toggle_ids(self):
        if self.ids_thread is None or not self.ids_thread.is_alive():
            self.ids_stop_event.clear()
            self.ids_thread = threading.Thread(target=self.start_ids, daemon=True)
            self.ids_thread.start()
            print(Fore.GREEN + "\nNIDPS started.")
            time.sleep(1)
        else:
            self.ids_stop_event.set()
            self.ids_thread.join(timeout=1)
            print(Fore.GREEN + "\nNIDPS stopped.")

    def live_traffic(self):
        print(Fore.BLUE + "\nViewing Live Traffic")
        print(Fore.YELLOW + "\n1. View Incoming Traffic")
        print(Fore.YELLOW + "2. View Outgoing Traffic")
        choice = input(Fore.CYAN + "Enter your choice (1-2): ").strip()
        if choice == "1":
            print(Fore.GREEN + "\nDisplaying Incoming Traffic...")
            self.traffic_monitor.listen_incoming()
        elif choice == "2":
            print(Fore.GREEN + "\nDisplaying Outgoing Traffic...")
            self.traffic_monitor.listen_outgoing()
        else:
            print(Fore.RED + "\nInvalid choice, returning to the menu...")

    def view_intrusion_logs(self):
        log_path = "./ids.log"
        print(Fore.BLUE + "\nViewing Intrusion Logs")
        try:
            with open(log_path, "r") as logfile:
                logs = logfile.read()
                print(Fore.GREEN + logs)
        except FileNotFoundError:
            print(Fore.RED + "\nNo intrusion logs found.")
        finally:
            input(Fore.MAGENTA + "\nPress Enter to return to the menu...")

    def display_blocked_ips(self):
        print(Fore.BLUE + "\nDisplaying Blocked IPs:")
        try:
            result = subprocess.run(["sudo", "iptables", "-L", "INPUT", "-n"], capture_output=True, text=True)
            print(Fore.GREEN + result.stdout)
        except Exception as e:
            print(Fore.RED + f"\nError retrieving blocked IPs: {e}")
        finally:
            input(Fore.MAGENTA + "\nPress Enter to return to the menu...")

    def clear_block_list(self):
        print(Fore.BLUE + "\nClearing Block List:")
        try:
            subprocess.run(["sudo", "iptables", "-F", "INPUT"], check=True)
            print(Fore.GREEN + "\nBlock list cleared.")
        except Exception as e:
            print(Fore.RED + f"\nError clearing block list: {e}")
        finally:
            input(Fore.MAGENTA + "\nPress Enter to return to the menu...")

    def unblock_ip(self):
        ip_to_unblock = input(Fore.CYAN + "\nEnter the IP address to unblock: ").strip()
        if ip_to_unblock:
            print(Fore.BLUE + f"\nAttempting to unblock IP: {ip_to_unblock}")
            try:
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip_to_unblock, "-j", "DROP"], check=True)
                print(Fore.GREEN + f"\nIP {ip_to_unblock} unblocked successfully.")
            except Exception as e:
                print(Fore.RED + f"\nError unblocking IP {ip_to_unblock}: {e}")
        else:
            print(Fore.RED + "\nNo IP provided.")
        input(Fore.MAGENTA + "\nPress Enter to return to the menu...")

    def run(self):
        while True:
            self.print_menu()
            choice = input(Fore.CYAN + "Enter your choice (1-7): ").strip()
            if choice == '1':
                self.toggle_ids()
            elif choice == '2':
                self.live_traffic()
            elif choice == '3':
                self.view_intrusion_logs()
            elif choice == '4':
                self.display_blocked_ips()
            elif choice == '5':
                self.clear_block_list()
            elif choice == '6':
                self.unblock_ip()
            elif choice == '7':
                print(Fore.RED + "\nExiting... Closing all threads...")
                if self.ids_thread and self.ids_thread.is_alive():
                    self.ids_stop_event.set()
                    self.ids_thread.join(timeout=1)
                print(Fore.RED + "Goodbye!")
                sys.exit(0)
            else:
                print(Fore.RED + "\nInvalid choice! Please try again.")
                input(Fore.MAGENTA + "\nPress Enter to return to the menu...")

if __name__ == "__main__":
    try:
        if os.geteuid() != 0:
            print(Fore.RED + "This script requires sudo privileges. Restarting with sudo...")
            subprocess.call(["sudo", sys.executable] + sys.argv)
            sys.exit(0)
    except AttributeError:
        print(Fore.RED + "Sudo check is not supported on this platform.")
    
    cli = IDSCLI()
    cli.run()