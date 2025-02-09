import subprocess
import time
import json
from scapy.all import rdpcap, TCP
import pyfiglet
import re
import os
import signal

# Configuration
pcap_file = "capture.pcap"
interface = "wlan0"  # Loopback interface
decoded_data_store = {}  # JSON object to store decoded data

# Suspicious Linux commands
suspicious_cmds = [
    "ls", "pwd", "cat", "wget", "curl", "nc", "bash", "sh", "chmod",
    "chown", "rm", "echo", "sudo", "scp", "ssh", "mv", "cp", "whoami",
    "ifconfig", "ip a", "netstat", "uname", "tar", "base64", "python", "perl"
]

def capture_traffic():
    """Captures network traffic for 10 seconds on lo and saves it as a PCAP file."""
    tshark_cmd = ["tshark", "-i", interface, "-w", pcap_file, "-F", "pcapng"]

    try:
        print(f"[*] Capturing packets on {interface} for 10 seconds...")
        process = subprocess.Popen(tshark_cmd)
        time.sleep(10)  # Capture for 10 seconds
        process.terminate()
        print(f"[+] Capture complete. Saved to {pcap_file}")
    except Exception as e:
        print(f"[ERROR] Capture failed: {e}")

def trace_and_kill_process(suspect_ip, suspect_port):
    """Traces and kills the process responsible for the suspicious connection."""
    try:
        netstat_cmd = f"netstat -tunp | grep {suspect_ip}:{suspect_port}"
        netstat_output = subprocess.getoutput(netstat_cmd)

        pid_match = re.search(r"\s(\d+)/", netstat_output)
        if pid_match:
            pid = pid_match.group(1)
            print(f"[!] Process ID (PID) found: {pid}")

            lsof_cmd = f"lsof -p {pid}"
            process_details = subprocess.getoutput(lsof_cmd)
            print(f"\n[+] Process Details:\n{process_details}")

            print(f"[!] Killing process {pid}...")
            os.kill(int(pid), signal.SIGKILL)
            print(f"[✔] Process {pid} terminated successfully.")
        else:
            print("[!] Could not determine the process ID.")
    except Exception as e:
        print(f"[ERROR] Process tracing failed: {e}")

def analyze_pcap():
    """Reads the PCAP file, extracts and decodes TCP stream data, then analyzes for threats."""
    global decoded_data_store
    try:
        packets = rdpcap(pcap_file)
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt[TCP].payload:
                payload = bytes(pkt[TCP].payload).decode(errors="ignore")
                src_ip = pkt[1].src  # Extract source IP
                src_port = pkt[TCP].sport  # Extract source port

                # Temporary variable to store decoded messages
                decoded_messages = []

                # Detect hex-encoded data and decode it
                hex_matches = re.findall(r'\b[0-9a-fA-F]{4,}\b', payload)
                for hex_str in hex_matches:
                    try:
                        decoded_data = bytes.fromhex(hex_str).decode(errors="ignore")
                        decoded_messages.append(decoded_data)
                    except Exception:
                        pass  # Ignore errors in decoding

                # Store decoded data in a JSON object
                decoded_data_store[f"{src_ip}:{src_port}"] = decoded_messages

                # Print extracted and decoded messages
                print(f"\n[+] Extracted TCP Stream Data from {src_ip}:{src_port}:")
                print(payload)
                if decoded_messages:
                    print("[+] Decoded Hex Messages:")
                    for msg in decoded_messages:
                        print(f"    - {msg}")

                # Check for suspicious commands in decoded messages
                for msg in decoded_messages:
                    for cmd in suspicious_cmds:
                        if cmd in msg:
                            print(f"\n[!] Suspicious Command Detected: {msg}")
                            print(f"[!] Source: {src_ip}:{src_port}")

                            # Display a warning using FIGlet
                            warning = pyfiglet.figlet_format("THREAT DETECTED")
                            print(warning)

                            # Trace and kill the process responsible
                            trace_and_kill_process(src_ip, src_port)
                            return  # Stop after first detection
    except Exception as e:
        print(f"[ERROR] Failed to analyze PCAP: {e}")

# Main Execution
if __name__ == "__main__":
    capture_traffic()  # Step 1: Capture traffic
    analyze_pcap()     # Step 2: Analyze and detect threats

    # Save decoded data to a JSON file
    with open("decoded_data.json", "w") as json_file:
        json.dump(decoded_data_store, json_file, indent=4)
    print("[+] Decoded data stored in decoded_data.json")
