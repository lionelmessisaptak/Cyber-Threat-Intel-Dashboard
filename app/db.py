from pymongo import MongoClient
from datetime import datetime

# Connect once and reuse
client = MongoClient("mongodb://localhost:27017/")
db = client["cti_dashboard"]

# Define all collections
file_uploads = db["file_uploads"]
vt_results = db["vt_results"]
lookups = db["lookups"]


def log_file_upload(file_hash, user_ip, filename, details=None):
    # Avoid duplicates by checking hash
    existing = file_uploads.find_one({"file_hash": file_hash})
    if existing:
        return  # Skip duplicate

    doc = {
        "file_hash": file_hash,
        "user_ip": user_ip,
        "filename": filename,
        "timestamp": datetime.utcnow()
    }

    if details:
        doc["details"] = details

    file_uploads.insert_one(doc)


def save_virustotal_result(file_hash, vt_data):
    vt_results.update_one(
        {"file_hash": file_hash},
        {
            "$set": {
                "vt_data": vt_data,
                "timestamp": datetime.utcnow()
            }
        },
        upsert=True
    )


def get_recent_scan_results(limit=20):
    return list(file_uploads.find().sort("timestamp", -1).limit(limit))


def save_ip_lookup_result(ip, data):
    entry = {
        "type": "ip_lookup",
        "ip": ip,
        "data": data,
        "timestamp": datetime.utcnow()
    }
    lookups.insert_one(entry)

def save_hash_lookup_result(sha256, vt_data):
    entry = {
        "type": "hash_lookup",
        "sha256": sha256,
        "timestamp": datetime.utcnow(),
        "vt_data": vt_data
    }
    db.lookups.insert_one(entry)
