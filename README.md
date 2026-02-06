## ARP Poisoner and PrintStream capture Tool

 * **Note:** do not steal my code, goblin
---

## Features

* **Targeted ARP Spoofing:** Focuses specifically on a single IP (e.g., your printer) to minimize network noise.
* **Automatic Interface Detection:** Uses Scapy's configuration to find your active network adapter automatically.
* **Session-Based PCAP Logging:** Saves network traffic into timestamped `.pcap` files organized by device folders.
* **Printer Port Filtering:** Specifically monitors Port **9100** (JetDirect) and Port **515** (LPD) to capture raw document streams.
* **Safety First:** Includes a robust restoration function to fix ARP tables on exit.
* **Google Drive Upload:** Automatically uploads extracted print jobs to Google Drive.

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

## Google Drive Setup

To enable automatic upload of extracted print jobs to Google Drive, follow these steps:

### Step 1: Create a Google Cloud Project

1. go to [Google Cloud Console](https://console.cloud.google.com/)
2. create a new project (or use an existing one)
3. Go to **APIs & Services → Library**
4. Search for **"Google Drive API"** and click **Enable**

### Step 2: Configure OAuth Consent Screen

1. Go to **APIs & Services → OAuth consent screen**
2. Select **External** and click **Create**
3. Fill in the required fields:
   - App name: `Print Extractor` (or any name)
   - User support email: Your email
   - Developer contact email: Your email
4. Click **Save and Continue**
5. On the Scopes page, click **Add or Remove Scopes**
6. Find and select: `https://www.googleapis.com/auth/drive.file`
7. Click **Update**, then **Save and Continue**
8. On the Test users page, click **Add Users**
9. **Add your own Gmail address** (the one you'll use to upload files)
10. Click **Save and Continue**

### Step 3: Create OAuth Credentials

1. Go to **APIs & Services → Credentials**
2. Click **Create Credentials → OAuth client ID**
3. Select **Web application** 
4. Give it a name
5. Under **Authorized redirect URIs**, click **Add URI**
6. Add this exact URI (no spaces!):
   ```
   https://developers.google.com/oauthplayground
   ```
7. Click **Create**
8. Copy the **Client ID** and **Client Secret** (you will need this later)

### Step 4: Get a Refresh Token

1. Go to: https://developers.google.com/oauthplayground/
2. Click the **gear icon** in the top right corner
3. Check **"Use your own OAuth credentials"**
4. Paste your **Client ID** and **Client Secret** from Step 3
5. Close the settings panel
6. In the left panel, find **"Drive API v3"** and select:
    `https://www.googleapis.com/auth/drive.file`
7. Click **"Authorize APIs"**
8. Log in with the **same Gmail you added as a test user**
9. Click **Allow** to grant access
10. Click **"Exchange authorization code for tokens"**
11. Copy the **Refresh token** (save this too)

### Step 5: Add Credentials to the Script

Open `scapy_extract_files.py` and find these lines near the top:

```python
CLIENT_ID = ""      # OAuth client ID
CLIENT_SECRET = ""  # OAuth client secret
REFRESH_TOKEN = ""  # refresh token
```
Paste the values from before to the fields.


Extracted files will be uploaded to a folder called **"Extracted_Print_Jobs"** in your Google Drive.

---

## Usage - very simple to use
* Run `start_ARPC.bat` for the live capture to start
* Run `python scapy_extract_files.py` to extract print jobs and upload to Google Drive

---

## Credits:
* **Cool Guy:** Almog
