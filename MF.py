import scapy.all as scapy

def scan(ip_range):
    # 1. Create an ARP Request packet for the IP range
    arp_request = scapy.ARP(pdst=ip_range)
    
    # 2. Create an Ethernet Broadcast packet (to send to everyone on the LAN)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # 3. Combine them into one packet
    arp_request_broadcast = broadcast/arp_request
    
    # 4. Send the packet and catch the responses
    # srp() sends and receives packets at layer 2 (Ethernet)
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # 5. Parse the responses into a readable format
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    
    return clients_list

def display_result(results_list):
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for client in results_list:
        print(f"{client['ip']}\t\t{client['mac']}")

if __name__ == "__main__":
    import subprocess
    import ipaddress
    import socket
    import re
    import sys

    def get_default_gateway():
        """Try to detect default gateway on Windows by parsing 'route print' or 'ipconfig'."""
        # Try 'route print' first
        try:
            out = subprocess.check_output(["route", "print"], text=True, errors="ignore")
            m = re.search(r'^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+', out, re.MULTILINE)
            if m:
                return m.group(1)
        except Exception:
            pass
        # Fallback to ipconfig parsing
        try:
            out = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
            # Find non-empty Default Gateway entries
            matches = re.findall(r'Default Gateway[ .:]*([\d\.]+)', out)
            for g in matches:
                if g and not g.startswith('0.0.0.0'):
                    return g
        except Exception:
            pass
        return None

    def get_local_ip():
        """Determine the local IP by opening a UDP socket (no packets sent)."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            return None
        finally:
            s.close()

    def get_netmask_for_ip(local_ip):
        """Parse 'ipconfig' output and find the subnet mask for the adapter that contains local_ip."""
        if not local_ip:
            return None
        try:
            out = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
            # Split into adapter blocks and look for the block that contains the local IP
            blocks = re.split(r'\r?\n\r?\n', out)
            for block in blocks:
                if local_ip in block:
                    m = re.search(r'Subnet Mask[ .:]*([\d\.]+)', block)
                    if m:
                        return m.group(1)
        except Exception:
            pass
        return None

    gw = get_default_gateway()
    local_ip = get_local_ip()
    netmask = get_netmask_for_ip(local_ip)

    # Compute the network/cidr to scan
    if local_ip and netmask:
        try:
            network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
            ip_range = f"{network.network_address}/{network.prefixlen}"
        except Exception:
            ip_range = None
    else:
        # Fallback: if we have gateway or local IP assume /24
        if gw:
            parts = gw.split('.')
            ip_range = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        elif local_ip:
            parts = local_ip.split('.')
            ip_range = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        else:
            ip_range = None

    print(f"Detected default gateway: {gw or 'unknown'}")
    print(f"Detected local IP: {local_ip or 'unknown'}")
    if ip_range:
        print(f"Using scan range: {ip_range}")
    else:
        print("Could not determine a network to scan. Please provide an IP range or run the script with administrator privileges.")
        sys.exit(1)

    try:
        scan_result = scan(ip_range)
        display_result(scan_result)
    except PermissionError:
        print("Permission denied: run this script as Administrator (required for sending raw packets on Windows).")
    except Exception as e:
        print(f"Error while scanning: {e}")