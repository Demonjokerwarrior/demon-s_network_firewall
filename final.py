import subprocess
import time
from scapy.all import rdpcap, TCP
import pyfiglet
import re
import os
import signal

# Configuration
pcap_file = "capture.pcap"
interface = "lo"  # Loopback interface

# Suspicious Linux commands
suspicious_cmds = [
    "ls", "pwd", "cat", "wget", "curl", "nc", "bash", "sh", "chmod",
    "chown", "rm", "echo", "sudo", "scp", "ssh", "mv", "cp", "whoami",
    "ifconfig", "ip a", "netstat", "uname", "tar", "base64", "python", "perl"
]

def capture_traffic():
    """Captures network traffic for 10 seconds on lo and saves it as a PCAP file."""
    tshark_cmd = [
        "tshark", "-i", interface, "-w", pcap_file, "-F", "pcapng"
    ]

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
        # Use netstat to find the process ID (PID) using the IP & port
        netstat_cmd = f"netstat -tunp | grep {suspect_ip}:{suspect_port}"
        netstat_output = subprocess.getoutput(netstat_cmd)

        pid_match = re.search(r"\s(\d+)/", netstat_output)
        if pid_match:
            pid = pid_match.group(1)
            print(f"[!] Process ID (PID) found: {pid}")

            # Get detailed process information using lsof
            lsof_cmd = f"lsof -p {pid}"
            process_details = subprocess.getoutput(lsof_cmd)
            print(f"\n[+] Process Details:\n{process_details}")

            # Kill the process
            print(f"[!] Killing process {pid}...")
            os.kill(int(pid), signal.SIGKILL)
            print(f"[✔] Process {pid} terminated successfully.")

        else:
            print("[!] Could not determine the process ID.")
    except Exception as e:
        print(f"[ERROR] Process tracing failed: {e}")

def analyze_pcap():
    """Reads the PCAP file and checks for suspicious Linux commands in TCP streams."""
    try:
        packets = rdpcap(pcap_file)
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt[TCP].payload:
                payload = bytes(pkt[TCP].payload).decode(errors="ignore")
                src_ip = pkt[1].src  # Extract source IP
                src_port = pkt[TCP].sport  # Extract source port

                # Check for any suspicious command in the payload
                for cmd in suspicious_cmds:
                    if cmd in payload:
                        print(f"[!] Suspicious Command Detected: {payload.strip()}")
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
