import argparse
import re
import gzip
import io
import base64
from pathlib import Path
from collections import defaultdict

try:
    from scapy.all import PcapReader, TCP, IP
except ImportError:
    raise SystemExit("Scapy is required. Install with: pip install scapy")

def canonical_session(pkt):
    a = (pkt[IP].src, pkt[TCP].sport)
    b = (pkt[IP].dst, pkt[TCP].dport)
    return (a, b) if a <= b else (b, a)

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
            try:
                clen = int(headers['content-length'])
                body = bytes_data[body_start:body_start+clen]
            except:
                body = bytes_data[body_start:]
        else:
            next_http = re.search(rb"HTTP/1\.[01] \d{3}", bytes_data[body_start:])
            body = bytes_data[body_start:body_start+next_http.start()] if next_http else bytes_data[body_start:]
        
        results.append((headers, body))
        idx = body_start + max(1, len(body))
    return results

def guess_extension(body):
    signatures = {
        b'\x89PNG\r\n\x1a\n': '.png',
        b'\xff\xd8\xff': '.jpg',
        b'\x47\x49\x46\x38': '.gif',
        b'\x50\x4b\x03\x04': '.zip',
        b'%PDF': '.pdf',
        b'MZ': '.exe',
        b'\x7fELF': '.elf',
        b'\x1f\x8b\x08': '.gz',
        b'PK\x03\x04': '.docx',
        b'\xd0\xcf\x11\xe0': '.doc',
        b'<html': '.html',
        b'<?xml': '.xml',
        b'{': '.json',
        b'[': '.json'
    }
    for sig, ext in signatures.items():
        if body.startswith(sig):
            return ext
    return '.bin'

def attempt_decode(body):
    if body.startswith(b'\x1f\x8b\x08'):
        try:
            return gzip.decompress(body), "Gzip Decoded"
        except: pass

    if len(body) > 10 and re.match(rb'^[A-Za-z0-9+/=\s]+$', body[:100]):
        try:
            return base64.b64decode(body), "Base64 Decoded"
        except: pass

    return body, None

def sanitize_filename(name):
    name = re.sub(r'[<>:"/\\|\?\*]', '_', name)
    return name[:200]

def process_and_save(headers, body, outdir, sess_id):
    if headers.get('content-encoding') == 'gzip':
        try:
            body = gzip.decompress(body)
        except: pass

    body, method = attempt_decode(body)
    if method:
        print(f"    [i] Action: {method}")

    fname = None
    if 'content-disposition' in headers:
        cd = headers['content-disposition']
        m = re.search(r'filename="?([^";]+)"?', cd)
        if m: fname = m.group(1)
    
    if not fname:
        ext = guess_extension(body)
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
    
    raw_streams = defaultdict(lambda: {'A->B': [], 'B->A': []})
    
    try:
        with PcapReader(args.pcap) as pcap_reader:
            for pkt in pcap_reader:
                if IP not in pkt or TCP not in pkt or not pkt[TCP].payload:
                    continue
                
                payload = bytes(pkt[TCP].payload)
                sess = canonical_session(pkt)
                a, _ = sess
                direction = 'A->B' if (pkt[IP].src, pkt[TCP].sport) == a else 'B->A'
                raw_streams[sess][direction].append((pkt[TCP].seq, payload))
    except Exception as e:
        print(f"Error: {e}")
        return

    total = 0
    for sess, dirs in raw_streams.items():
        sess_id = f"{sess[0][0]}_{sess[0][1]}"
        for dname, chunks in dirs.items():
            if not chunks: continue
            
            chunks.sort(key=lambda x: x[0])
            min_seq = chunks[0][0]
            max_end = max(s + len(b) for s, b in chunks)
            stream_data = bytearray(max_end - min_seq)
            for seq, b in chunks:
                offset = seq - min_seq
                stream_data[offset:offset+len(b)] = b
            
            responses = find_http_responses(bytes(stream_data))
            if responses:
                for headers, body in responses:
                    if len(body) < 50: continue 
                    saved_name = process_and_save(headers, body, outdir, sess_id)
                    print(f"Extracted: {saved_name}")
                    total += 1
            elif len(stream_data) > 10000: 
                raw_name = f"stream_{sess_id}_{dname}.raw"
                with open(outdir / raw_name, 'wb') as f:
                    f.write(stream_data)
                print(f"Saved raw stream: {raw_name}")

    print(f"Done. Saved {total} objects to {outdir}")

if __name__ == '__main__':
    main()