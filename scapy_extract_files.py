#!/usr/bin/env python3
"""
scapy_extract_files.py
Reassemble TCP streams from a pcap using Scapy, detect HTTP file transfers and save files.
Usage: python scapy_extract_files.py capture.pcap outdir

Limitations:
- Encrypted TLS/HTTPS cannot be decrypted here (you need TLS keys or an active MITM).
- This is a best-effort extractor for HTTP responses; other protocols are saved as raw streams.
"""

import argparse
import os
import re
from pathlib import Path
from collections import defaultdict

try:
    from scapy.all import rdpcap, TCP, Raw, IP
except Exception as e:
    raise SystemExit("Scapy is required. Install with: pip install scapy")


def read_pcap(path):
    return rdpcap(path)


def canonical_session(pkt):
    # Return canonical 4-tuple for session: ((ip1, port1), (ip2, port2)) with ordering
    a = (pkt[IP].src, pkt[TCP].sport)
    b = (pkt[IP].dst, pkt[TCP].dport)
    # canonicalize so that smaller tuple (lexicographically) comes first
    if a <= b:
        return (a, b)
    else:
        return (b, a)


def reassemble_streams(pkts):
    # streams: session -> {'A->B': [(seq, bytes), ...], 'B->A': [...]}
    streams = defaultdict(lambda: {'A->B': [], 'B->A': []})

    for pkt in pkts:
        if IP not in pkt or TCP not in pkt:
            continue
        if not pkt[TCP].payload:
            continue
        try:
            payload = bytes(pkt[TCP].payload)
        except Exception:
            continue
        sess = canonical_session(pkt)
        a, b = sess
        direction = 'A->B' if (pkt[IP].src, pkt[TCP].sport) == a else 'B->A'
        streams[sess][direction].append((pkt[TCP].seq, payload))

    # now build contiguous bytearray for each direction
    reassembled = {}
    for sess, dirs in streams.items():
        reassembled[sess] = {}
        for dname, segs in dirs.items():
            if not segs:
                reassembled[sess][dname] = b''
                continue
            # compute relative seqs by subtracting min seq
            min_seq = min(s for s, _ in segs)
            max_end = max(s + len(b) for s, b in segs)
            size = max_end - min_seq
            buf = bytearray(size)
            for seq, b in segs:
                offset = seq - min_seq
                buf[offset:offset+len(b)] = b
            reassembled[sess][dname] = bytes(buf)
    return reassembled


def find_http_responses(bytes_data):
    # return list of (start_index, header_dict, body_bytes)
    results = []
    idx = 0
    while True:
        m = re.search(rb"HTTP/1\.[01] \d{3}", bytes_data[idx:])
        if not m:
            break
        start = idx + m.start()
        # find header end
        hdr_end = bytes_data.find(b"\r\n\r\n", start)
        if hdr_end == -1:
            break
        headers_block = bytes_data[start:hdr_end].decode('latin1', errors='replace')
        headers_lines = headers_block.split('\r\n')
        headers = {}
        # first line is status
        headers['Status'] = headers_lines[0]
        for line in headers_lines[1:]:
            parts = line.split(':', 1)
            if len(parts) == 2:
                headers[parts[0].strip().lower()] = parts[1].strip()
        # determine body length
        body_start = hdr_end + 4
        if 'content-length' in headers:
            try:
                clen = int(headers['content-length'])
                body = bytes_data[body_start:body_start+clen]
            except Exception:
                body = bytes_data[body_start:]
        elif headers.get('transfer-encoding','').lower() == 'chunked':
            body = decode_chunked(bytes_data[body_start:])
        else:
            # no length info -> heuristically grab until next HTTP or end
            next_http = re.search(rb"HTTP/1\.[01] \d{3}", bytes_data[body_start:])
            if next_http:
                body = bytes_data[body_start:body_start+next_http.start()]
            else:
                body = bytes_data[body_start:]
        results.append((start, headers, body))
        idx = body_start + max(1, len(body))
    return results


def decode_chunked(b):
    out = bytearray()
    idx = 0
    while True:
        m = re.match(rb"([0-9A-Fa-f]+)\r\n", b[idx:])
        if not m:
            break
        length = int(m.group(1), 16)
        idx += m.end()
        if length == 0:
            # skip final CRLF
            idx += 2
            break
        out += b[idx:idx+length]
        idx += length + 2  # skip chunk and CRLF
    return bytes(out)


def guess_extension(data_bytes):
    if data_bytes.startswith(b'\x50\x4B\x03\x04'):
        return '.zip'
    if data_bytes.startswith(b'\x89PNG'):
        return '.png'
    if data_bytes.startswith(b'\xFF\xD8\xFF'):
        return '.jpg'
    if data_bytes.startswith(b'MZ'):
        return '.exe'
    if data_bytes.startswith(b'%PDF'):
        return '.pdf'
    return ''


def sanitize_filename(name: str) -> str:
    """Sanitize a filename for Windows/Unix filesystems: replace invalid chars with '_' and trim length."""
    if not name:
        return 'file'
    # Replace Windows-invalid characters and other problematic characters
    name = re.sub(r'[<>:"/\\|\?\*]', '_', name)
    # Replace whitespace sequences with single underscore
    name = re.sub(r'\s+', '_', name)
    # Replace any remaining non-alnum._- with underscore
    name = re.sub(r'[^A-Za-z0-9._-]', '_', name)
    # Trim to safe length (leave room for suffixes)
    return name[:240]


def save_http_objects(sess, direction_data, outdir):
    saved = []
    responses = find_http_responses(direction_data)
    for i, (start, headers, body) in enumerate(responses):
        # decide filename
        fname = None
        if 'content-disposition' in headers:
            cd = headers['content-disposition']
            m = re.search(r'filename="?([^";]+)"?', cd)
            if m:
                fname = m.group(1)
        if not fname:
            # fallback to status+offset
            fname = f"resp_{i}_{abs(hash((sess,start)))%100000}"
            ext = guess_extension(body)
            if ext:
                fname += ext
        # sanitize filename for filesystem
        fname = sanitize_filename(fname)
        path = Path(outdir) / fname
        # avoid overwriting by adding numeric suffix if necessary
        base = path.stem
        suffix = path.suffix
        counter = 1
        while path.exists():
            path = Path(outdir) / f"{base}_{counter}{suffix}"
            counter += 1
        try:
            with open(path, 'wb') as f:
                f.write(body)
            saved.append(path)
        except OSError as e:
            # fallback to simpler filename
            fallback = Path(outdir) / f"resp_{i}_{abs(hash((sess,start)))%100000}.bin"
            with open(fallback, 'wb') as f:
                f.write(body)
            saved.append(fallback)
    return saved


def main():
    parser = argparse.ArgumentParser(description='Extract files from pcap using Scapy (HTTP extractor)')
    parser.add_argument('pcap', help='pcap file to analyze')
    parser.add_argument('outdir', help='output directory')
    parser.add_argument('--min-bytes', type=int, default=1024, help='minimum response body size to save')
    args = parser.parse_args()

    pkts = read_pcap(args.pcap)
    streams = reassemble_streams(pkts)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    total_saved = 0
    for sess, dirs in streams.items():
        # we consider server->client direction to find HTTP responses. Heuristic: port 80 or 8080 or 8000 as server dport
        a, b = sess
        # check both directions for responses
        for dname in ('A->B', 'B->A'):
            data = dirs[dname]
            if not data or len(data) < args.min_bytes:
                continue
            responses = find_http_responses(data)
            if responses:
                saved = save_http_objects(sess, data, outdir)
                total_saved += len(saved)
                print(f"[+] Session {sess} {dname}: saved {len(saved)} HTTP object(s): {[str(p.name) for p in saved]}")
            else:
                # optionally write stream raw
                dname_safe = sanitize_filename(dname)
                fname = f"stream_{abs(hash(sess))%100000}_{dname_safe}.raw"
                path = outdir / fname
                # avoid overwriting
                counter = 1
                base = Path(path).stem
                suffix = Path(path).suffix
                while path.exists():
                    path = outdir / f"{base}_{counter}{suffix}"
                    counter += 1
                try:
                    with open(path, 'wb') as f:
                        f.write(data)
                    print(f"[i] Session {sess} {dname}: no HTTP objects, saved raw stream -> {path.name}")
                except OSError:
                    # fallback to safe generic name
                    fallback = outdir / f"stream_{abs(hash(sess))%100000}_{counter}.raw"
                    with open(fallback, 'wb') as f:
                        f.write(data)
                    print(f"[i] Session {sess} {dname}: no HTTP objects, saved raw stream -> {fallback.name}")

    print(f"Done. Total saved objects: {total_saved}")


if __name__ == '__main__':
    main()
