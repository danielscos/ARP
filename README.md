# ARP Capture & Extractor 🔧

Simple, one-command usage:

- **To run the Program** double-click `start_ARPC.bat` or right-click and "Run as administrator" — this runs `python ARPC.py` with the privileges needed for ARP spoofing. 

What happens when you run it:

- The tool starts ARP spoofing, writes a timestamped pcap to your **Downloads** folder (`captured_<timestamp>.pcap`), and runs a local extractor periodically to save HTTP objects into `decrypted_out/`.
- If a TLS keylog file is present (auto-detected from `SSLKEYLOGFILE` env var or common locations), the script will use it and will also run `tshark` (if installed) to export decrypted HTTP objects.

Enabling TLS keylog (quick):

1. Set an environment variable `SSLKEYLOGFILE` to a writable path (example PowerShell):

   ```powershell
   $env:SSLKEYLOGFILE = "C:\Users\%USERNAME%\sslkeylog.log"
   Start-Process "C:\Program Files\Mozilla Firefox\firefox.exe" -NoNewWindow
   ```

   Or set it persistently (requires new session):

   ```powershell
   setx SSLKEYLOGFILE "%USERPROFILE%\sslkeylog.log"
   ```

2. Start the browser from the same environment so it writes keys to that file.

Notes:

- `tshark` is optional; if it exists and a keylog file is present, the script will use it to export HTTP objects. If not present, the built-in scapy extractor still runs and saves raw streams.

- Praise Almog a gever