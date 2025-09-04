#!/usr/bin/env python3
"""
Accurate Cyber Defense Network Quick Scanner
A command-line based network monitoring and security tool
"""

import threading
import time
import subprocess
import socket
import json
import os
import sys
import logging
from datetime import datetime
from collections import deque
import requests
import ping3
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.sendrecv import sr1
import argparse
import signal

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cyber_tool.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AccurateCyberDefense")


class Accuratecyberdefense:
    def __init__(self):
        self.monitored_ips = set()
        self.monitoring_active = False
        self.telegram_token = None
        self.telegram_chat_id = None
        self.command_history = deque(maxlen=100)
        self.ping_results = {}
        self.monitoring_thread = None
        self.stop_monitoring = threading.Event()
        self.running = True
        
        # Load configuration if exists
        self.load_config()
        
        # Handle Ctrl+C gracefully
        signal.signal(signal.SIGINT, self.signal_handler)
        
        print("=" * 60)
        print("🔐 Accurate Cyber Defense Network Quick Scanner")
        print("=" * 60)
        print("Type 'help' for available commands or 'exit' to quit.")
        print()

    def signal_handler(self, signum, frame):
        """Handle SIGINT (Ctrl+C) gracefully"""
        print("\n\n🛑 Shutting down gracefully...")
        self.stop_monitoring_cmd()
        self.save_config()
        sys.exit(0)

    def run(self):
        """Main CLI loop"""
        while self.running:
            try:
                # Display prompt
                status_indicator = "🟢" if self.monitoring_active else "⚪"
                monitored_count = len(self.monitored_ips)
                prompt = f"CyberTool [{status_indicator} {monitored_count} IPs] > "
                
                command = input(prompt).strip()
                
                if command:
                    self.process_command(command)
                    
            except EOFError:
                print("\nGoodbye!")
                break
            except KeyboardInterrupt:
                print("\n\nUse 'exit' command to quit properly.")
                continue
            except Exception as e:
                print(f"❌ Error: {str(e)}")

    def process_command(self, cmd):
        """Process user command"""
        if not cmd:
            return
        
        # Add to command history
        self.command_history.append(cmd)
        
        # Process command
        parts = cmd.split()
        command = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        try:
            if command == "help":
                self.show_help()
            elif command == "ping":
                if len(args) < 1:
                    print("❌ Usage: ping <ip_address>")
                else:
                    self.ping_ip(args[0])
            elif command == "start":
                if len(args) < 2 or args[0] != "monitoring":
                    print("❌ Usage: start monitoring <ip_address> or start monitoring all")
                else:
                    if args[1] == "all":
                        self.start_monitoring_all()
                    else:
                        self.start_monitoring_ip(args[1])
            elif command == "stop":
                self.stop_monitoring_cmd()
            elif command == "view":
                self.view_monitored_ips()
            elif command == "status":
                self.show_status()
            elif command == "exit" or command == "quit":
                self.exit_tool()
            elif command == "clear":
                self.clear_screen()
            elif command == "config":
                self.handle_config_command(args)
            elif command == "test":
                self.handle_test_command(args)
            elif command == "history":
                self.show_command_history()
            elif command == "add":
                if len(args) < 2 or args[0] != "ip":
                    print("❌ Usage: add ip <ip_address>")
                else:
                    self.add_ip(args[1])
            elif command == "remove":
                if len(args) < 2 or args[0] != "ip":
                    print("❌ Usage: remove ip <ip_address>")
                else:
                    self.remove_ip(args[1])
            elif command == "udptraceroute":
                if len(args) < 1:
                    print("❌ Usage: udptraceroute <ip_address>")
                else:
                    self.udp_traceroute(args[0])
            elif command == "tcptraceroute":
                if len(args) < 1:
                    print("❌ Usage: tcptraceroute <ip_address>")
                else:
                    self.tcp_traceroute(args[0])
            elif command == "scan":
                if len(args) < 1:
                    print("❌ Usage: scan <ip_address> [port_range]")
                else:
                    port_range = args[1] if len(args) > 1 else "1-1000"
                    self.port_scan(args[0], port_range)
            elif command == "info":
                if len(args) < 1:
                    print("❌ Usage: info <ip_address>")
                else:
                    self.get_ip_info(args[0])
            else:
                print("❌ Unknown command. Type 'help' for available commands.")
                
        except Exception as e:
            print(f"❌ Error executing command: {str(e)}")
            logger.error(f"Command execution error: {str(e)}")

    def handle_config_command(self, args):
        """Handle config command with subcommands"""
        if len(args) < 2:
            print("❌ Usage: config telegram token <token> or config telegram chat_id <chat_id>")
            return
            
        if args[0] == "telegram":
            if args[1] == "token" and len(args) >= 3:
                self.config_telegram_token(args[2])
            elif args[1] == "chat_id" and len(args) >= 3:
                self.config_telegram_chat_id(args[2])
            else:
                print("❌ Usage: config telegram token <token> or config telegram chat_id <chat_id>")
        else:
            print("❌ Unknown config option. Type 'help' for available commands.")

    def handle_test_command(self, args):
        """Handle test command with subcommands"""
        if len(args) < 2:
            print("❌ Usage: test telegram connection")
            return
            
        if args[0] == "telegram" and args[1] == "connection":
            self.test_telegram_connection()
        else:
            print("❌ Unknown test option. Type 'help' for available commands.")

    def show_help(self):
        """Display help information"""
        help_text = """
📖 Available Commands:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔍 Network Operations:
  ping <ip_address>              - Ping an IP address
  scan <ip_address> [port_range] - Port scan (default: 1-1000)
  info <ip_address>              - Get IP information
  udptraceroute <ip_address>     - UDP traceroute
  tcptraceroute <ip_address>     - TCP traceroute

📊 Monitoring:
  add ip <ip_address>            - Add IP to monitoring list
  remove ip <ip_address>         - Remove IP from monitoring list
  view                           - View all monitored IPs
  start monitoring <ip|all>      - Start monitoring
  stop                           - Stop monitoring
  status                         - Show monitoring status

⚙️  Configuration:
  config telegram token <token>  - Set Telegram bot token
  config telegram chat_id <id>   - Set Telegram chat ID
  test telegram connection       - Test Telegram connection

🛠️  Utility:
  history                        - Show command history
  clear                          - Clear screen
  help                           - Show this help
  exit/quit                      - Exit the tool

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        print(help_text)

    def ping_ip(self, ip):
        """Ping an IP address"""
        print(f"🔍 Pinging {ip}...")
        
        try:
            # Use ping3 library for cross-platform ping
            response_time = ping3.ping(ip, timeout=2)
            
            if response_time is not False and response_time is not None:
                print(f"✅ Reply from {ip}: time={round(response_time * 1000)}ms")
                self.ping_results[ip] = f"{round(response_time * 1000)}ms"
            else:
                print(f"❌ Request timed out for {ip}")
                self.ping_results[ip] = "Timeout"
        except Exception as e:
            print(f"❌ Error pinging {ip}: {str(e)}")
            self.ping_results[ip] = f"Error: {str(e)}"

    def port_scan(self, ip, port_range):
        """Perform a port scan on an IP address"""
        print(f"🔍 Scanning ports on {ip} (range: {port_range})...")
        
        try:
            if "-" in port_range:
                start_port, end_port = map(int, port_range.split("-"))
            else:
                start_port = end_port = int(port_range)
            
            open_ports = []
            total_ports = end_port - start_port + 1
            
            for port in range(start_port, end_port + 1):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    
                    if result == 0:
                        open_ports.append(port)
                        print(f"  ✅ Port {port}: Open")
                    
                    sock.close()
                    
                    # Progress indicator
                    if port % 100 == 0 or port == end_port:
                        progress = ((port - start_port + 1) / total_ports) * 100
                        print(f"  📊 Progress: {progress:.1f}%")
                        
                except Exception as e:
                    continue
            
            if open_ports:
                print(f"✅ Scan complete. Open ports: {open_ports}")
            else:
                print("❌ No open ports found in the specified range.")
                
        except Exception as e:
            print(f"❌ Error scanning {ip}: {str(e)}")

    def get_ip_info(self, ip):
        """Get information about an IP address"""
        print(f"🔍 Getting information for {ip}...")
        
        try:
            # Try to get hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                print(f"  🏠 Hostname: {hostname}")
            except socket.herror:
                print(f"  🏠 Hostname: Not available")
            
            # Ping test
            response_time = ping3.ping(ip, timeout=2)
            if response_time is not False and response_time is not None:
                print(f"  📶 Ping: {round(response_time * 1000)}ms")
            else:
                print(f"  📶 Ping: Not responding")
            
            # Try to get geolocation info (using a free API)
            try:
                geo_response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    if geo_data["status"] == "success":
                        print(f"  🌍 Country: {geo_data.get('country', 'Unknown')}")
                        print(f"  🏙️  City: {geo_data.get('city', 'Unknown')}")
                        print(f"  🏢 ISP: {geo_data.get('isp', 'Unknown')}")
            except:
                print(f"  🌍 Geolocation: Not available")
                
        except Exception as e:
            print(f"❌ Error getting IP info: {str(e)}")

    def start_monitoring_ip(self, ip):
        """Start monitoring a specific IP address"""
        if ip not in self.monitored_ips:
            print(f"❌ IP {ip} is not in the monitored list. Use 'add ip {ip}' first.")
            return
        
        if self.monitoring_active:
            print("❌ Monitoring is already active.")
            return
        
        self.monitoring_active = True
        self.stop_monitoring.clear()
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self.monitor_ips, args=([ip],))
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        
        print(f"✅ Started monitoring IP: {ip}")

    def start_monitoring_all(self):
        """Start monitoring all IP addresses"""
        if not self.monitored_ips:
            print("❌ No IP addresses to monitor. Use 'add ip <ip_address>' first.")
            return
        
        if self.monitoring_active:
            print("❌ Monitoring is already active.")
            return
        
        self.monitoring_active = True
        self.stop_monitoring.clear()
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self.monitor_ips, args=(list(self.monitored_ips),))
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        
        print(f"✅ Started monitoring all IPs: {len(self.monitored_ips)} addresses")

    def stop_monitoring_cmd(self):
        """Stop monitoring"""
        if not self.monitoring_active:
            print("❌ Monitoring is not active.")
            return
        
        self.monitoring_active = False
        self.stop_monitoring.set()
        
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        
        print("✅ Monitoring stopped.")

    def view_monitored_ips(self):
        """View all monitored IP addresses"""
        if not self.monitored_ips:
            print("❌ No IP addresses being monitored.")
            return
        
        print("📋 Monitored IP addresses:")
        for i, ip in enumerate(sorted(self.monitored_ips), 1):
            status = self.ping_results.get(ip, "Unknown")
            print(f"  {i}. {ip} - Status: {status}")

    def show_status(self):
        """Show current monitoring status"""
        print("\n📊 System Status:")
        print("━" * 40)
        print(f"🔄 Monitoring: {'🟢 Active' if self.monitoring_active else '⚪ Inactive'}")
        print(f"📱 Monitored IPs: {len(self.monitored_ips)}")
        print(f"📱 Telegram: {'✅ Configured' if self.telegram_token and self.telegram_chat_id else '❌ Not configured'}")
        
        if self.ping_results:
            print(f"📊 Recent ping results:")
            for ip, result in list(self.ping_results.items())[-5:]:
                print(f"  • {ip}: {result}")
        print("━" * 40)

    def exit_tool(self):
        """Exit the tool"""
        if self.monitoring_active:
            self.stop_monitoring_cmd()
        
        self.save_config()
        print("👋 Goodbye! Stay secure!")
        self.running = False

    def clear_screen(self):
        """Clear the screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
        print("🔐 CLI Cyber Security Monitoring Tool")
        print("=" * 60)

    def config_telegram_token(self, token):
        """Configure Telegram bot token"""
        self.telegram_token = token
        print("✅ Telegram token configured.")
        self.save_config()

    def config_telegram_chat_id(self, chat_id):
        """Configure Telegram chat ID"""
        self.telegram_chat_id = chat_id
        print("✅ Telegram chat ID configured.")
        self.save_config()

    def test_telegram_connection(self):
        """Test Telegram connection"""
        if not self.telegram_token or not self.telegram_chat_id:
            print("❌ Telegram not configured. Set token and chat ID first.")
            return
        
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/getMe"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                print("✅ Telegram connection test successful.")
                
                # Send a test message
                message = "🔐 Cyber Security Tool: Telegram connection test successful!"
                if self.send_telegram_message(message):
                    print("✅ Test message sent successfully.")
                else:
                    print("❌ Failed to send test message.")
            else:
                print(f"❌ Telegram connection test failed: {response.text}")
        except Exception as e:
            print(f"❌ Telegram connection test failed: {str(e)}")

    def send_telegram_message(self, message):
        """Send a message via Telegram"""
        if not self.telegram_token or not self.telegram_chat_id:
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            data = {
                "chat_id": self.telegram_chat_id,
                "text": message
            }
            response = requests.post(url, data=data, timeout=10)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to send Telegram message: {str(e)}")
            return False

    def show_command_history(self):
        """Show command history"""
        if not self.command_history:
            print("❌ No command history.")
            return
        
        print("📜 Command history:")
        for i, cmd in enumerate(list(self.command_history)[-10:], 1):  # Show last 10 commands
            print(f"  {i}. {cmd}")

    def add_ip(self, ip):
        """Add an IP address to monitor"""
        # Validate IP address
        try:
            socket.inet_aton(ip)
            if ip in self.monitored_ips:
                print(f"⚠️  IP {ip} is already in the monitored list.")
            else:
                self.monitored_ips.add(ip)
                print(f"✅ Added IP: {ip}")
                self.save_config()
        except socket.error:
            print(f"❌ Invalid IP address: {ip}")

    def remove_ip(self, ip):
        """Remove an IP address from monitoring"""
        if ip in self.monitored_ips:
            self.monitored_ips.remove(ip)
            print(f"✅ Removed IP: {ip}")
            self.save_config()
        else:
            print(f"❌ IP {ip} is not in the monitored list.")

    def udp_traceroute(self, ip):
        """Perform UDP traceroute to an IP"""
        print(f"🔍 Performing UDP traceroute to {ip}...")
        print(f"{'Hop':<4} {'IP Address':<16} {'Response Time'}")
        print("-" * 40)
        
        try:
            port = 33434  # Standard traceroute port
            ttl = 1
            max_hops = 30
            timeout = 2
            
            while ttl <= max_hops:
                # Create a UDP packet with increasing TTL
                packet = IP(dst=ip, ttl=ttl) / UDP(dport=port)
                
                # Send the packet and wait for a response
                start_time = time.time()
                reply = sr1(packet, verbose=0, timeout=timeout)
                elapsed_time = (time.time() - start_time) * 1000
                
                if reply is None:
                    print(f"{ttl:<4} {'*':<16} {'*'}")
                elif reply.type == 3:  # Destination unreachable
                    print(f"{ttl:<4} {reply.src:<16} {elapsed_time:.2f} ms (Destination)")
                    break
                else:
                    print(f"{ttl:<4} {reply.src:<16} {elapsed_time:.2f} ms")
                
                ttl += 1
                
                # Check if we've reached the destination
                if reply is not None and reply.src == ip:
                    break
                    
        except Exception as e:
            print(f"❌ Error performing UDP traceroute: {str(e)}")

    def tcp_traceroute(self, ip):
        """Perform TCP traceroute to an IP"""
        print(f"🔍 Performing TCP traceroute to {ip}...")
        print(f"{'Hop':<4} {'IP Address':<16} {'Response Time'}")
        print("-" * 40)
        
        try:
            port = 80  # HTTP port
            ttl = 1
            max_hops = 30
            timeout = 2
            
            while ttl <= max_hops:
                # Create a TCP SYN packet with increasing TTL
                packet = IP(dst=ip, ttl=ttl) / TCP(dport=port, flags="S")
                
                # Send the packet and wait for a response
                start_time = time.time()
                reply = sr1(packet, verbose=0, timeout=timeout)
                elapsed_time = (time.time() - start_time) * 1000
                
                if reply is None:
                    print(f"{ttl:<4} {'*':<16} {'*'}")
                elif reply.haslayer(TCP) and reply.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    print(f"{ttl:<4} {reply.src:<16} {elapsed_time:.2f} ms (Destination)")
                    break
                elif reply.haslayer(ICMP):
                    print(f"{ttl:<4} {reply.src:<16} {elapsed_time:.2f} ms")
                else:
                    print(f"{ttl:<4} {reply.src:<16} {elapsed_time:.2f} ms")
                
                ttl += 1
                
                # Check if we've reached the destination
                if reply is not None and reply.src == ip:
                    break
                    
        except Exception as e:
            print(f"❌ Error performing TCP traceroute: {str(e)}")

    def monitor_ips(self, ips_to_monitor):
        """Monitor IP addresses for availability"""
        check_interval = 60  # Check every 60 seconds
        
        print(f"🔄 Monitoring started for {len(ips_to_monitor)} IP addresses")
        
        # Initial status check
        ip_status = {}
        for ip in ips_to_monitor:
            ip_status[ip] = self.check_ip_status(ip)
        
        # Continuous monitoring
        while not self.stop_monitoring.is_set():
            try:
                for ip in ips_to_monitor:
                    if self.stop_monitoring.is_set():
                        break
                    
                    current_status = self.check_ip_status(ip)
                    
                    # Check if status changed
                    if ip in ip_status and ip_status[ip] != current_status:
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        message = f"🚨 [{timestamp}] Status change for {ip}: {ip_status[ip]} -> {current_status}"
                        print(message)
                        
                        # Send Telegram notification if configured
                        if self.telegram_token and self.telegram_chat_id:
                            self.send_telegram_message(message)
                    
                    ip_status[ip] = current_status
                
                # Wait for next check
                time.sleep(check_interval)
                
            except Exception as e:
                print(f"❌ Error in monitoring thread: {str(e)}")
                time.sleep(check_interval)
        
        print("🔄 Monitoring stopped")

    def check_ip_status(self, ip):
        """Check the status of an IP address"""
        try:
            # Try to ping the IP
            response = ping3.ping(ip, timeout=2)
            
            if response is not False and response is not None:
                self.ping_results[ip] = f"{round(response * 1000)}ms"
                return "Online"
            else:
                self.ping_results[ip] = "Timeout"
                return "Offline"
        except Exception as e:
            self.ping_results[ip] = f"Error: {str(e)}"
            return f"Error: {str(e)}"

    def load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists("cyber_tool_config.json"):
                with open("cyber_tool_config.json", "r") as f:
                    config = json.load(f)
                
                self.monitored_ips = set(config.get("monitored_ips", []))
                self.telegram_token = config.get("telegram_token")
                self.telegram_chat_id = config.get("telegram_chat_id")
                
                logger.info("Configuration loaded successfully.")
        except Exception as e:
            print(f"⚠️  Error loading configuration: {str(e)}")
            logger.error(f"Configuration load error: {str(e)}")

    def save_config(self):
        """Save configuration to file"""
        try:
            config = {
                "monitored_ips": list(self.monitored_ips),
                "telegram_token": self.telegram_token,
                "telegram_chat_id": self.telegram_chat_id
            }
            
            with open("cyber_tool_config.json", "w") as f:
                json.dump(config, f, indent=2)
            
            logger.info("Configuration saved successfully.")
        except Exception as e:
            print(f"⚠️  Error saving configuration: {str(e)}")
            logger.error(f"Configuration save error: {str(e)}")


def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(description="CLI Cyber Security Monitoring Tool")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--version", action="version", version="CLI Cyber Security Tool v1.0")
    
    args = parser.parse_args()
    
    try:
        # Check if running as root (required for some network operations)
        if os.geteuid() != 0:
            print("⚠️  Warning: Running without root privileges. Some features may not work.")
            print("   Consider running with sudo for full functionality.")
            print()
    except AttributeError:
        # Windows doesn't have geteuid
        pass
    
    # Create and run the tool
    tool = Accuratecyberdefense()
    tool.run()


if __name__ == "__main__":
    main()
