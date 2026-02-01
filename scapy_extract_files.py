import argparse
import re
import gzip
import io
from pathlib import Path
from collections import defaultdict

try:
    from scapy.all import rdpcap, TCP, IP
except ImportError:
    raise SystemExit("Scapy is required. Install with: pip install scapy")


def read_pcap(path):
    return rdpcap(path)

def canonical_session(pkt):
    a = (pkt[IP].src, pkt[TCP].sport)
    b = (pkt[IP].dst, pkt[TCP].dport)
    return (a, b) if a <= b else (b, a)

def reassemble_streams(pkts):
    streams = defaultdict(lambda: {'A->B': [], 'B->A': []})
    for pkt in pkts:
        if IP not in pkt or TCP not in pkt or not pkt[TCP].payload:
            continue
        
        try:
            payload = bytes(pkt[TCP].payload)
        except Exception:
            continue
            
        sess = canonical_session(pkt)
        a, _ = sess
        direction = 'A->B' if (pkt[IP].src, pkt[TCP].sport) == a else 'B->A'
        streams[sess][direction].append((pkt[TCP].seq, payload))

    reassembled = {}
    for sess, dirs in streams.items():
        reassembled[sess] = {}
        for dname, segs in dirs.items():
            if not segs: continue
            min_seq = min(s for s, _ in segs)
            max_end = max(s + len(b) for s, b in segs)
            buf = bytearray(max_end - min_seq)
            for seq, b in segs:
                offset = seq - min_seq
                buf[offset:offset+len(b)] = b
            reassembled[sess][dname] = bytes(buf)
    return reassembled

def find_http_responses(bytes_data):
    results = []
    idx = 0
    while True:
        m = re.search(rb"HTTP/1\.[01] \d{3}", bytes_data[idx:])
        if not m: break
        
        start = idx + m.start()
        hdr_end = bytes_data.find(b"\r\n\r\n", start)
        if hdr_end == -1: break
        
        headers_block = bytes_data[start:hdr_end].decode('latin1', errors='replace')
        lines = headers_block.split('\r\n')
        headers = {'status': lines[0]}
        for line in lines[1:]:
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip().lower()] = v.strip()
        
        body_start = hdr_end + 4
        if headers.get('transfer-encoding') == 'chunked':
            body = decode_chunked(bytes_data[body_start:])
        elif 'content-length' in headers:
            clen = int(headers['content-length'])
            body = bytes_data[body_start:body_start+clen]
        else:
            next_http = re.search(rb"HTTP/1\.[01] \d{3}", bytes_data[body_start:])
            body = bytes_data[body_start:body_start+next_http.start()] if next_http else bytes_data[body_start:]
        
        results.append((headers, body))
        idx = body_start + max(1, len(body))
    return results

def decode_chunked(b):
    out = bytearray()
    idx = 0
    while True:
        m = re.match(rb"([0-9A-Fa-f]+)\r\n", b[idx:])
        if not m: break
        length = int(m.group(1), 16)
        idx += m.end()
        if length == 0: break
        out += b[idx:idx+length]
        idx += length + 2
    return bytes(out)

def guess_extension(body, headers):
    if body.startswith(b'\x89PNG\r\n\x1a\n'): return '.png'
    if body.startswith(b'\xff\xd8\xff'): return '.jpg'
    if body.startswith(b'\x50\x4b\x03\x04'): return '.zip'
    if body.startswith(b'%PDF'): return '.pdf'
    if body.startswith(b'MZ'): return '.exe'
    
    ctype = headers.get('content-type', '')
    if 'image/gif' in ctype: return '.gif'
    if 'text/html' in ctype: return '.html'
    if 'application/json' in ctype: return '.json'
    if 'text/javascript' in ctype: return '.js'
    
    return '.bin'

def sanitize_filename(name):
    name = re.sub(r'[<>:"/\\|\?\*]', '_', name)
    return name[:200]

def process_and_save(headers, body, outdir, sess_id):
    if headers.get('content-encoding') == 'gzip':
        try:
            body = gzip.decompress(body)
        except Exception:
            pass

    fname = None
    if 'content-disposition' in headers:
        cd = headers['content-disposition']
        m = re.search(r'filename="?([^";]+)"?', cd)
        if m: fname = m.group(1)
    
    if not fname:
        ext = guess_extension(body, headers)
        fname = f"extracted_{sess_id}_{hash(body) % 1000}{ext}"
    
    path = Path(outdir) / sanitize_filename(fname)
    
    counter = 1
    original_path = path
    while path.exists():
        path = original_path.with_name(f"{original_path.stem}_{counter}{original_path.suffix}")
        counter += 1
        
    with open(path, 'wb') as f:
        f.write(body)
    return path.name

def main():
    parser = argparse.ArgumentParser(description='HTTP File Extractor')
    parser.add_argument('pcap', help='Path to pcap')
    parser.add_argument('outdir', help='Output directory')
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    
    print(f"[*] Reading {args.pcap}...")
    pkts = read_pcap(args.pcap)
    streams = reassemble_streams(pkts)
    
    total = 0
    for sess, dirs in streams.items():
        sess_id = f"{sess[0][0]}_{sess[0][1]}"
        for dname, data in dirs.items():
            responses = find_http_responses(data)
            if responses:
                for headers, body in responses:
                    if len(body) < 100: continue
                    saved_name = process_and_save(headers, body, outdir, sess_id)
                    print(f"[+] Extracted: {saved_name}")
                    total += 1
            elif len(data) > 5000:
                raw_name = f"raw_stream_{sess_id}_{dname}.raw"
                with open(outdir / raw_name, 'wb') as f:
                    f.write(data)
                print(f"[i] Saved raw stream: {raw_name}")

    print(f"\n[!] Done. Saved {total} HTTP objects.")

if __name__ == '__main__':
    main()