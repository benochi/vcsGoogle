import os
import hashlib
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

SCOPES = ['https://www.googleapis.com/auth/drive.file']

class DriveUploader:
    def __init__(self, gui):
        self.gui = gui
        self.creds = None
        self.service = None
        self.authenticate_google_drive()

    def authenticate_google_drive(self):
        self.gui.log("Authenticating with Google Drive...")
        if os.path.exists('token.json'):
            self.creds = Credentials.from_authorized_user_file('token.json', SCOPES)
        # Refresh or authenticate
        if not self.creds or not self.creds.valid:
            if self.creds and self.creds.expired and self.creds.refresh_token:
                self.creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                self.creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
            with open('token.json', 'w') as token:
                token.write(self.creds.to_json())
        self.service = build('drive', 'v3', credentials=self.creds)
        self.gui.log("Authentication successful.")

    def compute_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.gui.log(f"Error computing hash for {file_path}: {e}")
            return None

    def get_drive_files(self, folder_id):
        files = {}
        page_token = None
        while True:
            response = self.service.files().list(
                q=f"'{folder_id}' in parents and trashed=false",
                spaces='drive',
                fields='nextPageToken, files(id, name, md5Checksum)',
                pageToken=page_token
            ).execute()
            for file in response.get('files', []):
                files[file['name']] = {
                    'id': file['id'],
                    'md5Checksum': file.get('md5Checksum')
                }
            page_token = response.get('nextPageToken', None)
            if page_token is None:
                break
        return files

    def upload_file(self, file_path, folder_id, existing_file_id=None):
        file_name = os.path.basename(file_path)
        self.gui.log(f"Uploading {file_name}...")
        file_metadata = {'name': file_name, 'parents': [folder_id]}
        media = MediaFileUpload(file_path, resumable=True)
        try:
            if existing_file_id:
                file = self.service.files().update(
                    fileId=existing_file_id,
                    media_body=media,
                    fields='id'
                ).execute()
            else:
                file = self.service.files().create(
                    body=file_metadata,
                    media_body=media,
                    fields='id'
                ).execute()
            self.gui.log(f"Successfully uploaded {file_name}.")
        except Exception as e:
            self.gui.log(f"Failed to upload {file_name}: {e}")

    def ensure_folder(self, folder_name, parent_id=None):
        query = f"name = '{folder_name}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
        if parent_id:
            query += f" and '{parent_id}' in parents"
        response = self.service.files().list(
            q=query,
            spaces='drive',
            fields='files(id, name)'
        ).execute()
        files = response.get('files', [])
        if files:
            return files[0]['id']
        else:
            file_metadata = {
                'name': folder_name,
                'mimeType': 'application/vnd.google-apps.folder'
            }
            if parent_id:
                file_metadata['parents'] = [parent_id]
            folder = self.service.files().create(body=file_metadata, fields='id').execute()
            self.gui.log(f"Created folder '{folder_name}'.")
            return folder.get('id')

    def push_changes(self, local_folder):
        self.gui.log(f"Scanning local folder: {local_folder}")
        local_files = {}
        for root, dirs, files in os.walk(local_folder):
            for file in files:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, local_folder)
                file_hash = self.compute_file_hash(file_path)
                if file_hash:
                    local_files[relative_path] = {
                        'path': file_path,
                        'hash': file_hash
                    }

        # Ensure a specific folder in Drive, e.g., "UE_Project_Backup"
        drive_folder_id = self.ensure_folder("UE_Project_Backup")

        # Get existing files on Drive
        drive_files = self.get_drive_files(drive_folder_id)

        # Determine which files to upload
        for relative_path, info in local_files.items():
            file_name = relative_path.replace("\\", "/")  # Normalize path
            drive_file = drive_files.get(relative_path)
            if drive_file:
                # Compare hashes
                if drive_file['md5Checksum'] != info['hash']:
                    # Upload updated file
                    self.upload_file(info['path'], drive_folder_id, existing_file_id=drive_file['id'])
            else:
                # New file, upload it
                self.upload_file(info['path'], drive_folder_id)

        self.gui.log("All changes have been pushed.")

# Tkinter GUI Setup
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("UE Project Google Drive Uploader")

        # Folder Selection
        self.folder_label = tk.Label(root, text="Select UE Project Folder:")
        self.folder_label.pack(pady=5)

        self.folder_path = tk.StringVar()
        self.folder_entry = tk.Entry(root, textvariable=self.folder_path, width=50)
        self.folder_entry.pack(pady=5)

        self.browse_button = tk.Button(root, text="Browse", command=self.browse_folder)
        self.browse_button.pack(pady=5)

        # Upload Button
        self.upload_button = tk.Button(root, text="Push Changes to Google Drive", command=self.start_upload)
        self.upload_button.pack(pady=10)

        # Log Area
        self.log_area = scrolledtext.ScrolledText(root, width=80, height=20, state='disabled')
        self.log_area.pack(pady=10)

    def browse_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.folder_path.set(folder_selected)

    def log(self, message):
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')

    def start_upload(self):
        local_folder = self.folder_path.get()
        if not os.path.isdir(local_folder):
            messagebox.showerror("Error", "Please select a valid folder.")
            return
        self.log("Starting upload process...")
        self.upload_button.config(state='disabled')
        self.root.update()

        uploader = DriveUploader(self)
        uploader.push_changes(local_folder)

        self.upload_button.config(state='normal')
        self.log("Upload process completed.")

# MediaFileUpload import
from googleapiclient.http import MediaFileUpload

def main():
    root = tk.Tk()
    app = App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
