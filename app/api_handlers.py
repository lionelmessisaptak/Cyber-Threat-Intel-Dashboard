# --- app/api_handlers.py ---
import os
import requests
import ipaddress
import time
import hashlib
from datetime import datetime

def check_ip(ip):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"error": "AbuseIPDB API key is missing. Check your .env file."}

    if not ip:
        return {"error": "No IP address provided."}

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"error": "Invalid IP address format."}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip.strip(), "maxAgeInDays": 90, "verbose": True}

    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"AbuseIPDB returned status {response.status_code}", "details": response.json()}
    except requests.exceptions.RequestException as e:
        return {"error": "Request to AbuseIPDB failed", "details": str(e)}

def scan_hash(file_hash):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY not found in environment variables."}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()  # ✅ Return raw VT structure
        elif response.status_code == 404:
            return {"error": f"Hash not found: {file_hash}"}
        elif response.status_code == 403:
            return {"error": "Forbidden: API key may lack permission or be invalid"}
        else:
            return {"error": f"VirusTotal returned {response.status_code}", "details": response.json()}
    except requests.exceptions.RequestException as e:
        return {"error": "Request to VirusTotal failed", "details": str(e)}

def upload_to_virustotal(file):
    import hashlib
    import json

    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY not found in environment variables."}

    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key}

    # Read and hash file
    file.stream.seek(0)
    file_bytes = file.stream.read()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    file.stream.seek(0)

    try:
        response = requests.post(url, headers=headers, files={"file": (file.filename, file.stream)})
        print(f"[DEBUG] VirusTotal upload response code: {response.status_code}")

        if response.status_code == 200:
            print("[DEBUG] Upload success.")
            data = response.json().get("data", {})
            return {
                "message": "Upload successful",
                "sha256": sha256_hash,
                "analysis_id": data.get("id"),
                "scan_link": f"https://www.virustotal.com/gui/file/{sha256_hash}"
            }

        elif response.status_code == 409:
            print("[DEBUG] 409 received. File already exists. Switching to scan_hash.")
            return {
                "message": "File already exists on VirusTotal",
                "sha256": sha256_hash,
                "scan_link": f"https://www.virustotal.com/gui/file/{sha256_hash}",
                "existing": True
            }

        else:
            print(f"[DEBUG] VT returned error code {response.status_code}")
            return {"error": f"VT returned {response.status_code}", "details": response.json()}

    except Exception as e:
        print(f"[DEBUG] Exception during upload: {e}")
        return {"error": str(e)}




def get_analysis_result(analysis_id):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": "API key not found."}

    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Could not fetch analysis result ({response.status_code})", "details": response.json()}
    except requests.exceptions.RequestException as e:
        return {"error": "Request to VirusTotal failed", "details": str(e)}

def poll_analysis_result(analysis_id, retries=8, delay=5):
    print(f"[DEBUG] Starting poll for analysis_id: {analysis_id}")
    for attempt in range(retries):
        result = get_analysis_result(analysis_id)
        status = result.get("data", {}).get("attributes", {}).get("status")
        print(f"[DEBUG] Poll attempt {attempt+1}: status = {status}")

        if status == "completed":
            return result

        time.sleep(delay)

    print("[DEBUG] Timed out waiting for VirusTotal analysis to complete.")
    return {"error": "Timed out waiting for scan to complete."}

