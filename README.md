# CognitoMail: EML File Phishing Analyzer
CognitoMail is a Python Flask web application designed to analyze Email Message (.eml) files for potential phishing attempts, spam characteristics, and security vulnerabilities. It processes email headers, body content, and attachments to generate a comprehensive risk score and a downloadable report.

# Features
Email Authentication Check: Analyzes headers for SPF, DKIM, and DMARC results and domain alignment.

Content Scanning: Scans the email body and subject for high-risk phishing keywords (e.g., "urgent," "password," "verify") and suspicious URL patterns.

URL/IP Analysis: Extracts all URLs and checks for domain/sender mismatches, shortened links, and URLs using raw IP addresses.

Attachment Check: Flags suspicious file extensions (.exe, .js, etc.).

CVE Detection: Scans the email content for keywords linked to known Common Vulnerabilities and Exposures (CVEs).

VirusTotal Lookup: Performs lookups for the sender's domain and any unique domains found in the body to check reputation.

PDF Reporting: Generates a detailed, downloadable PDF report of the analysis using WeasyPrint.

# Deployment and Setup
Prerequisites
Python 3.8+

pip (Python package installer)

Optional: A VirusTotal API Key (to enable the VT lookup feature).

1. Clone the Repository

git clone [YOUR_REPOSITORY_URL]
cd CognitoMail/project
2. Create and Activate Virtual Environment
It is highly recommended to use a virtual environment to manage dependencies.

Windows (PowerShell):

python -m venv .venv
. .\.venv\Scripts\Activate

macOS / Linux:

python3 -m venv .venv
source .venv/bin/activate
3. Install Dependencies
The application relies on libraries like Flask, requests, and WeasyPrint for PDF generation.

pip install -r requirements.txt
4. Configure VirusTotal (Optional)
If you have a VirusTotal API Key, set it as an environment variable in your terminal session before starting the app:


Windows
$env:VT_API_KEY="YOUR_API_KEY_HERE"

macOS / Linux
export VT_API_KEY="YOUR_API_KEY_HERE"
5. Run the Application

python app.py
The application will start running on http://127.0.0.1:5000/.

# Project Structure
The core application logic is located within the project/ directory:

project/
├── app.py              # Main Flask application and analysis logic
├── requirements.txt    # Required Python packages (includes WeasyPrint)
├── render.yaml         # Render Deployment configuration file
├── templates/          # HTML templates (index, result, pdf_report)
├── cve_list.json       # Database for CVE keyword scanning
└── ...
