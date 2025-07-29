from flask import Blueprint, request, render_template, redirect, url_for, flash, current_app
from app.api_handlers import check_ip, scan_hash, get_analysis_result, upload_to_virustotal, poll_analysis_result
from datetime import datetime, timedelta
from app.db import log_file_upload, save_virustotal_result, get_recent_scan_results, save_ip_lookup_result, save_hash_lookup_result
import hashlib
from app.db import db
from dotenv import set_key, load_dotenv
from pathlib import Path
import os ,re
from config import HOST, PORT
import subprocess
import sys
import webbrowser
from config import BASE_DIR
from app import mongo
from collections import Counter
from pymongo import DESCENDING
import feedparser
from pymongo import collection



env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
load_dotenv(dotenv_path=env_path)

routes_blueprint = Blueprint("routes", __name__)

@routes_blueprint.route('/')
def dashboard():
    # ---- SCAN STAT COUNTS ----
    total_scans = (
        mongo.db.file_uploads.count_documents({}) +
        mongo.db.lookups.count_documents({}) +
        mongo.db.vt_results.count_documents({})
    )

    malicious_file_uploads = mongo.db.file_uploads.count_documents({"details.malicious_count": {"$gt": 0}})
    malicious_vt_results = mongo.db.vt_results.count_documents({
        "data.data.attributes.last_analysis_stats.malicious": {"$gt": 0}
    })

    malicious_count = malicious_file_uploads + malicious_vt_results
    clean_count = total_scans - malicious_count

    # ---- TOP THREATS ----
    top_threats_data = []

    # IP threats (abuse score > 0)
    ip_threats_pipeline = [
        {"$match": {
            "type": "ip_lookup",
            "malicious": True,
            "data.abuseConfidenceScore": {"$gt": 0}
        }},
        {"$group": {
            "_id": "$value",
            "abuse_score": {"$first": "$data.abuseConfidenceScore"}
        }},
        {"$sort": {"abuse_score": -1}},
        {"$limit": 5}
    ]
    ip_threats = list(mongo.db.lookups.aggregate(ip_threats_pipeline))

    for ip in ip_threats:
        top_threats_data.append({
            "value": ip['_id'],
            "count": ip['abuse_score'],
            "type": "IP"
        })

    # Hash threats from VT
    hash_threats_vt_pipeline = [
        {"$match": {"data.data.attributes.last_analysis_stats.malicious": {"$gt": 0}}},
        {"$group": {"_id": "$sha256", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    hash_threats_vt = list(mongo.db.vt_results.aggregate(hash_threats_vt_pipeline))

    for h in hash_threats_vt:
        top_threats_data.append({
            "value": h['_id'],
            "count": h['count'],
            "type": "Hash"
        })

    # Hash threats from file uploads
    hash_threats_upload_pipeline = [
        {"$match": {"details.malicious_count": {"$gt": 0}}},
        {"$group": {"_id": "$file_hash", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    hash_threats_upload = list(mongo.db.file_uploads.aggregate(hash_threats_upload_pipeline))

    for h in hash_threats_upload:
        doc = mongo.db.file_uploads.find_one({"file_hash": h['_id']})
        filename = doc.get("filename") if doc else h['_id']
        top_threats_data.append({
            "value": filename,
            "count": h['count'],
            "type": "Hash"
        })

    # ---- RECENT DOCS ----
    file_uploads = list(mongo.db.file_uploads.find().sort("timestamp", -1).limit(5))
    lookups = list(mongo.db.lookups.find().sort("timestamp", -1).limit(5))
    vt_results = list(mongo.db.vt_results.find().sort("timestamp", -1).limit(5))
    recent_ip_lookups = list(mongo.db.lookups.find({"type": "ip_lookup"}).sort("timestamp", -1).limit(5))

    def format_docs(docs, fields_map):
        for doc in docs:
            ts = doc.get("timestamp")
            doc["timestamp"] = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "Unknown"
            for k, v in fields_map.items():
                doc[k] = doc.get(v, "N/A")
        return docs

    file_uploads = format_docs(file_uploads, {"filename": "filename", "sha256": "file_hash"})
    lookups = format_docs(lookups, {"value": "value", "type": "type"})
    vt_results = format_docs(vt_results, {"sha256": "sha256"})
    recent_ip_lookups = format_docs(recent_ip_lookups, {"value": "value", "type": "type"})

    for doc in file_uploads:
        details = doc.get("details", {})
        doc["malicious_count"] = details.get("malicious_count", 0)
        doc["total_engines"] = details.get("total_engines", 0)

    for doc in vt_results:
        attr = doc.get("data", {}).get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        doc["malicious_count"] = stats.get("malicious", 0)
        doc["total_engines"] = sum(stats.values()) if stats else 0
        doc["status"] = "Malicious" if doc["malicious_count"] > 0 else "Clean"

    return render_template(
        'dashboard.html',
        total_scans=total_scans,
        malicious_scans=malicious_count,
        clean_scans=clean_count,
        top_threats=top_threats_data,
        file_uploads=file_uploads,
        lookups=lookups,
        vt_results=vt_results,
        recent_ip_lookups=recent_ip_lookups
    )






@routes_blueprint.route("/lookup", methods=["GET", "POST"])
def lookup():
    result = {}
    selected_type = "ip"
    reports = []
    query = ""
    message = ""
    last_reported = None
    total_reports = 0

    if request.method == "POST":
        selected_type = request.form.get("query_type")
        query = request.form.get("query_value", "").strip()

        if not query:
            message = "Missing query input."
        else:
            if selected_type == "ip":
                response = check_ip(query)
                if "error" not in response:
                    result = response.get("data", {})
                    reports = result.get("reports", [])
                    last_reported = result.get("lastReportedAt", "")
                    total_reports = result.get("totalReports", 0)
                    save_ip_lookup_result(query, result)  # Save IP data to MongoDB
                else:
                    message = response.get("error", "Error during IP lookup")

            elif selected_type == "hash":
                vt_response = scan_hash(query)
                if "error" in vt_response:
                    message = vt_response["error"]
                else:
                    attributes = vt_response.get("data", {}).get("attributes", {})
                    analysis_stats = attributes.get("last_analysis_stats", {})

                    result = {
                        "sha256": attributes.get("sha256", query),
                        "status": "Malicious" if analysis_stats.get("malicious", 0) > 0 else "Clean",
                        "first_seen": datetime.utcfromtimestamp(attributes.get("first_submission_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if attributes.get("first_submission_date") else "Unknown",
                        "last_analysis": datetime.utcfromtimestamp(attributes.get("last_analysis_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if attributes.get("last_analysis_date") else "Unknown",
                        "malicious_count": analysis_stats.get("malicious", 0),
                        "total_engines": sum(analysis_stats.values()),
                    }

                    # 🔐 Save hash lookup to DB if not already present
                    save_hash_lookup_result(query, vt_response)


    return render_template("lookup.html",
                           result=result,
                           reports=reports,
                           selected_type=selected_type,
                           query=query,
                           message=message,
                           last_reported=last_reported,
                           total_reports=total_reports)


@routes_blueprint.route("/result/<analysis_id>")
def view_analysis_result(analysis_id):
    result = get_analysis_result(analysis_id)
    return render_template("lookup.html", result=result, selected_type="ip")


def hash_function(data):
    return hashlib.sha256(data).hexdigest()


@routes_blueprint.route("/upload", methods=["GET", "POST"])
def upload_file():
    if request.method == "POST":
        if "file" not in request.files:
            return render_template("upload.html", error="No file part in request.")

        file = request.files["file"]
        if file.filename == "":
            return render_template("upload.html", error="No file selected.")

        file.stream.seek(0)
        sha256 = hashlib.sha256(file.stream.read()).hexdigest()
        file.stream.seek(0)

        existing_report = scan_hash(sha256)
        scan_data = {
            "sha256": sha256,
            "vt_link": f"https://www.virustotal.com/gui/file/{sha256}"
        }

        if "error" not in existing_report:
            print("[DEBUG] File already exists — using existing VT data")
            analysis = existing_report

            attributes = analysis.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            scan_data.update({
                "status": "Malicious" if stats.get("malicious", 0) > 0 else "Clean",
                "first_seen": datetime.utcfromtimestamp(attributes.get("first_submission_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if attributes.get("first_submission_date") else "Unknown",
                "last_analysis": datetime.utcfromtimestamp(attributes.get("last_analysis_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if attributes.get("last_analysis_date") else "Unknown",
                "malicious_count": stats.get("malicious", 0),
                "total_engines": sum(stats.values())
            })

            save_virustotal_result(scan_data, attributes)
            log_file_upload(
                file_hash=scan_data["sha256"],
                user_ip=request.remote_addr,
                filename=file.filename,
                details=scan_data
            )


            return render_template("upload.html", result=scan_data, show_refresh=True)

        else:
            print("[DEBUG] File not found — uploading to VT")
            result = upload_to_virustotal(file)

            if "analysis_id" in result:
                scan_data.update({
                    "status": "Scanning in Progress",
                    "first_seen": "N/A",
                    "last_analysis": "N/A",
                    "malicious_count": "-",
                    "total_engines": "-",
                    "analysis_id": result["analysis_id"]
                })

                log_file_upload(
                    file_hash=scan_data["sha256"],
                    user_ip=request.remote_addr,
                    filename=file.filename,
                    details=scan_data
                )


                return render_template("upload.html", result=scan_data, show_refresh=True)
            else:
                return render_template("upload.html", error="Upload failed.")

    return render_template("upload.html")


@routes_blueprint.route("/refresh/<sha256>", methods=["GET"])
def refresh_scan(sha256):
    vt_response = scan_hash(sha256)
    attributes = vt_response.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    result = {
        "sha256": sha256,
        "status": "Malicious" if stats.get("malicious", 0) > 0 else "Clean",
        "first_seen": datetime.utcfromtimestamp(attributes.get("first_submission_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if attributes.get("first_submission_date") else "Unknown",
        "last_analysis": datetime.utcfromtimestamp(attributes.get("last_analysis_date", 0)).strftime("%Y-%m-%d %H:%M:%S") if attributes.get("last_analysis_date") else "Unknown",
        "malicious_count": stats.get("malicious", 0),
        "total_engines": sum(stats.values()),
        "vt_link": f"https://www.virustotal.com/gui/file/{sha256}"
    }

    save_virustotal_result(result, attributes)
    return render_template("upload.html", result=result, show_refresh=True)

@routes_blueprint.route("/logs")
def scan_results():
    # IP Lookups
    ip_results = list(
        db.lookups.find({"type": "ip_lookup"}).sort("timestamp", -1).limit(20)
    )
    for doc in ip_results:
        ts = doc.get("timestamp")
        doc["timestamp"] = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "Unknown"
        doc["ip"] = doc.get("data", {}).get("ipAddress", "N/A")
        doc["country"] = doc.get("data", {}).get("countryCode", "Unknown")
        doc["abuse_score"] = doc.get("data", {}).get("abuseConfidenceScore", "N/A")

    # Hash Lookups
    hash_results = list(
        db.lookups.find({"type": "hash_lookup"}).sort("timestamp", -1).limit(20)
    )
    for doc in hash_results:
        ts = doc.get("timestamp")
        doc["timestamp"] = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "Unknown"
        doc["sha256"] = doc.get("sha256", "N/A")
        attr = doc.get("data", {}).get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        doc["malicious_count"] = stats.get("malicious", 0)
        doc["total_engines"] = sum(stats.values()) if stats else 0
        doc["status"] = "Malicious" if doc["malicious_count"] > 0 else "Clean"

    # File Uploads
    file_uploads = list(db.file_uploads.find().sort("timestamp", -1).limit(20))
    for doc in file_uploads:
        ts = doc.get("timestamp")
        doc["timestamp"] = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "Unknown"
        doc["filename"] = doc.get("filename", "unknown")
        doc["sha256"] = doc.get("file_hash", "N/A")
        details = doc.get("details", {})
        doc["malicious_count"] = details.get("malicious_count", 0)
        doc["total_engines"] = details.get("total_engines", 0)

    return render_template(
        "logs.html",
        ip_logs=ip_results,
        hash_logs=hash_results,
        file_logs=file_uploads
    )

env_path = Path('.') / '.env'  # Assuming .env is in project root

@routes_blueprint.route('/settings', methods=['GET'])
def settings():
    return render_template("settings.html", host=HOST, port=PORT)


@routes_blueprint.route('/save-api-keys', methods=['POST'])
def save_api_keys():
    vt_key = request.form.get("vt_api")
    abuse_key = request.form.get("abuse_api")

    if vt_key:
        set_key(env_path, "VIRUSTOTAL_API_KEY", vt_key)
    if abuse_key:
        set_key(env_path, "ABUSEIPDB_API_KEY", abuse_key)

    # 🔄 Reload updated env into current session
    load_dotenv(dotenv_path=env_path, override=True)

    flash("API keys saved successfully.")  # ✅ shows message on frontend
    return redirect(url_for("routes.settings"))


@routes_blueprint.route('/save-host-port', methods=['POST'])
def save_host_port():
    host = request.form.get("host")
    port = request.form.get("port")

    config_path = os.path.join(BASE_DIR, "config.py")

    with open(config_path, "r") as f:
        lines = f.readlines()

    with open(config_path, "w") as f:
        for line in lines:
            if line.startswith("HOST"):
                f.write(f'HOST = "{host}"\n')
            elif line.startswith("PORT"):
                f.write(f'PORT = {port}\n')
            else:
                f.write(line)

    # Flash the update message
    flash("Host and port updated. Restarting server...")

    # Build the command to restart
    python_path = sys.executable
    runpy_path = os.path.join(BASE_DIR, "run.py")

    # Open the browser to the new URL
    url = f"http://{host}:{port}"
    webbrowser.open(url)

    # Restart run.py with new host/port
    subprocess.Popen([python_path, runpy_path])

    # Kill current process
    os._exit(0)





