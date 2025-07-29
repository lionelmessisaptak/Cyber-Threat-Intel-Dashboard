# Cyber Threat Intel Dashboard

A web-based Cyber Threat Intelligence Dashboard built with Flask and MongoDB. It integrates with VirusTotal and AbuseIPDB APIs to provide real-time threat analysis, file scanning, and detailed scan logs — all with a clean and interactive UI.

## Features

- IP Address Lookup using AbuseIPDB
- File Upload and Hash Scanning using VirusTotal
- IP, hash, and file scan logs stored in MongoDB
- Dashboard with clean vs malicious detection stats
- Live Threat Feed and Top Threats sections
- Settings page to manage API keys and server configuration
- Modular layout with separate HTML, CSS, and JS

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/lionelmessisaptak/Cyber-Threat-Intel-Dashboard.git
   cd Cyber-Threat-Intel-Dashboard
2.Create and activate a virtual environment:
  ```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
3.Install dependencies:
  ```bash
pip install -r requirements.txt
```
4.Start the Flask app:
  ```bash
flask run
```
The app will run on http://127.0.0.1:5000/ by default.
## API Key Configuration

You do not need to manually edit any config files. Just:

1. Open the app in your browser.
2. Go to the **Settings** page.
3. Enter your **VirusTotal** and **AbuseIPDB** API keys.
4. Click **Save**. The keys are securely stored and used across the app.

---

## MongoDB Setup

Make sure MongoDB is installed and running locally or remotely.

The following collections are used:

- `ip_logs` – for IP lookups
- `hash_logs` – for hash scan results
- `file_logs` – for file upload records

> Note: MongoDB URI and other connection settings can be configured via the **Settings** page as well (if implemented).

---

## Usage

- **IP Lookup**: Analyze an IP for abuse score, ISP, ASN, usage type, and other metadata.
- **Hash Lookup**: Submit a file hash (MD5, SHA1, SHA256) to retrieve known scan results.
- **File Upload**: Upload files to scan them using VirusTotal and get detailed results.
- **Logs Page**: View historical logs for all IP lookups, hash lookups, and file uploads.
- **Dashboard**: View clean vs malicious detection stats, live threat feeds, and top threats.
- **Settings**: Configure API keys and server settings directly from the interface.

---

## Project Structure

Cyber-Threat-Intel-Dashboard/

├── app/

│ ├── templates/ # HTML templates (Jinja2)

│ ├── static/ # CSS and JS assets

│ ├── routes.py # Flask routes

│ ├── api_handlers.py # VirusTotal & AbuseIPDB logic

│ └── ...

├── requirements.txt # Python dependencies

├── run.py # Flask entry point

└── README.md # Project documentation


---

## Notes

- Works with **free** VirusTotal and AbuseIPDB API keys (subject to rate limits).
- Clean separation of backend, frontend, and API logic.
- Easily extensible for more data sources, threat feeds, or alerting systems.
