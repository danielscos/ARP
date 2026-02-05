## ARP Poisoner and PrintStream capture Tool

* **do not steal my code, goblin** 
---

## Features

* **Targeted ARP Spoofing:** Focuses specifically on a single IP (e.g., your printer) to minimize network noise.
* **Automatic Interface Detection:** Uses Scapy’s configuration to find your active network adapter automatically.
* **Session-Based PCAP Logging:** Saves network traffic into timestamped `.pcap` files organized by device folders.
* **Printer Port Filtering:** Specifically monitors Port **9100** (JetDirect) and Port **515** (LPD) to capture raw document streams.
* **Safety First:** Includes a robust restoration function to fix ARP tables on exit.

---

## Requirements

Before running the tool, run Setup.bat. or ensure you have the following installed:

1. **Python 3.10+**
2. **Npcap:** Required for raw packet sniffing on Windows. [Download here](https://npcap.com/). 
3. **Administrative Privileges:** The terminal must be run as Administrator to access the network stack.

---

## Installation
**just install the zip file**

---

## Usage - very simple to use
* Run start_ARPC.bat for the live capture to start

---

## Credits:
* **Cool Guy:** Almog
