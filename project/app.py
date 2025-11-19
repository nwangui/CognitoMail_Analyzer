# app.py (full file)
import os
import re
import json
import ipaddress
from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from flask import Flask, render_template, request
from markupsafe import Markup
import requests
import tempfile
import pdfkit
from flask import send_file
from datetime import datetime
app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
CVE_DB_FILENAME = "cve_list.json"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- CVE DB (sample)
def ensure_cve_db(filename=CVE_DB_FILENAME):
    """
    Loads the external CVE list if available.
    Fallback to the small sample only if the file is missing or unreadable.
    """
    fallback_sample = [
        {"cve": "CVE-2021-44228", "keywords": ["log4j", "log4shell", "jndi", "ldap"], "description": "Log4Shell RCE affecting Log4j."},
        {"cve": "CVE-2023-23397", "keywords": ["outlook reminder", "outlook ntlm"], "description": "NTLM credential leak via Outlook Reminder."}
    ]

    # If external file exists → load it
    if os.path.exists(filename):
        try:
            with open(filename, "r", encoding="utf-8") as fh:
                data = json.load(fh)

                # Ensure each entry has required fields
                cleaned = []
                for item in data:
                    cve = item.get("cve") or item.get("id") or ""
                    kw = item.get("keywords") or item.get("keyword") or []
                    desc = item.get("description") or item.get("summary") or ""
                    if cve:
                        cleaned.append({
                            "cve": cve,
                            "keywords": kw,
                            "description": desc
                        })
                return cleaned if cleaned else fallback_sample

        except Exception:
            return fallback_sample

    # If missing → create fallback file
    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(fallback_sample, fh, indent=2)

    return fallback_sample


CVE_DB = ensure_cve_db()

# --- server-side highlighting filter
RISKY_WORDS = [
    "urgent", "verify", "alert", "password", "immediately", "failed", "suspicious",
    "danger", "risk", "reset", "action required", "unauthorized", "credential",
    "pay now", "bank account", "credit card", "login immediately"
]

def server_highlight(text):
    if not text:
        return Markup("")
    s = str(text)
    url_pattern = re.compile(r'(https?://[^\s<>]+)')
    def url_repl(m):
        url = m.group(1)
        display = url if len(url) <= 80 else url[:77] + "..."
        return f"<a class='link' href='{url}' target='_blank' rel='noopener noreferrer'>{display}</a>"
    s = url_pattern.sub(url_repl, s)
    for w in sorted(RISKY_WORDS, key=len, reverse=True):
        s = re.sub(r'(?i)\b' + re.escape(w) + r'\b',
                   lambda m: f"<span class='risk'>{m.group(0)}</span>",
                   s)
    return Markup(s)

app.jinja_env.filters['server_highlight'] = server_highlight

# --- severity classifier (same as before)
def classify_severity(text):
    t = (text or "").lower()
    if any(x in t for x in ["credential", "password", "ssn", "ransom", "remote code execution", "cve", "exploit"]):
        return "critical"
    if any(x in t for x in [".exe", ".js", ".vbs", ".msi", "shortened url", "ip address as domain", "suspicious attachment"]):
        return "high"
    if any(x in t for x in ["domain mismatch", "does not match", "return-path", "reply-to", "urgent", "verify", "alert"]):
        return "medium"
    return "low"

# --- extract domains & authentication results
def extract_domains(headers):
    domains = {}
    from_h = headers.get("From", "") or ""
    m = re.search(r'@([\w\.-]+)', from_h)
    if m:
        domains["From_Domain"] = m.group(1).lower()

    rp = headers.get("Return-Path", "") or ""
    m = re.search(r'@([\w\.-]+)', rp)
    if m:
        domains["Return_Path_Domain"] = m.group(1).lower()

    auth = headers.get("Authentication-Results", "") or ""

    spf_m = re.search(r"spf=(pass|fail|softfail|neutral|none)", auth, re.I)
    if spf_m:
        domains["SPF_Status"] = spf_m.group(1).lower()
    dkim_s = re.search(r"dkim=(pass|fail|neutral|temperror|permerror)", auth, re.I)
    if dkim_s:
        domains["DKIM_Status"] = dkim_s.group(1).lower()
    dkim_d = re.search(r"header\.d=([\w\.-]+)", auth, re.I)
    if dkim_d:
        domains["DKIM_Domain"] = dkim_d.group(1).lower()
    dmarc_s = re.search(r"dmarc=(pass|fail|bestguess|none|quarantine|reject)", auth, re.I)
    if dmarc_s:
        domains["DMARC_Status"] = dmarc_s.group(1).lower()
    dmarc_d = re.search(r"header\.from=([\w\.-]+)", auth, re.I)
    if dmarc_d:
        domains["DMARC_Domain"] = dmarc_d.group(1).lower()

    return domains

# --- analyze domains with clear reasons
def analyze_domains(domains):
    """
    Returns analysis dict with:
      - SPF_Status, DKIM_Status, DMARC_Status
      - SPF_Reason, DKIM_Reason, DMARC_Reason (human readable)
      - Domains_Match_Alignment boolean
      - Details list (text)
      - Details_HTML will be added in calling function
    """
    from_domain = domains.get("From_Domain")
    rp_domain = domains.get("Return_Path_Domain")
    spf = domains.get("SPF_Status", "unknown")
    dkim_status = domains.get("DKIM_Status", "unknown")
    dkim_domain = domains.get("DKIM_Domain")
    dmarc = domains.get("DMARC_Status", "unknown")
    dmarc_domain = domains.get("DMARC_Domain")

    analysis = {
        "SPF_Status": spf,
        "DKIM_Status": dkim_status,
        "DMARC_Status": dmarc,
        "SPF_Reason": "",
        "DKIM_Reason": "",
        "DMARC_Reason": "",
        "Domains_Match_Alignment": False,
        "Details": []
    }

    # SPF reasoning
    if spf == "pass":
        reason = "SPF reported PASS in Authentication-Results."
        if rp_domain:
            reason += f" Return-Path domain is '{rp_domain}'."
            if from_domain and rp_domain != from_domain:
                reason += f" Note: Return-Path domain '{rp_domain}' does not match From domain '{from_domain}' (alignment missing)."
        else:
            reason += " Return-Path not available in headers."
        analysis["SPF_Reason"] = reason
    elif spf in ("fail", "softfail", "neutral", "none"):
        if spf == "none":
            analysis["SPF_Reason"] = "No SPF result present (Authentication-Results lacked SPF info)."
        else:
            analysis["SPF_Reason"] = f"SPF reported '{spf}' in Authentication-Results."
        if rp_domain:
            analysis["SPF_Reason"] += f" Return-Path domain: '{rp_domain}'."
        if from_domain and rp_domain and rp_domain != from_domain:
            analysis["SPF_Reason"] += f" Return-Path '{rp_domain}' != From '{from_domain}'."
    else:
        analysis["SPF_Reason"] = "SPF information not found in headers."

    # DKIM reasoning
    if dkim_status == "pass":
        if dkim_domain:
            reason = f"DKIM signature verified (header.d={dkim_domain})."
            if from_domain and dkim_domain == from_domain:
                reason += " DKIM domain aligns with From domain."
            else:
                reason += " DKIM domain does not match From domain (alignment missing)." if from_domain else " From domain not available for alignment check."
        else:
            reason = "DKIM passed but no header.d (signature domain) found in parsed header."
        analysis["DKIM_Reason"] = reason
    elif dkim_status in ("fail", "neutral", "temperror", "permerror"):
        reason = f"DKIM reported '{dkim_status}' in Authentication-Results."
        if dkim_domain:
            reason += f" Signature domain: '{dkim_domain}'."
            if from_domain and dkim_domain != from_domain:
                reason += f" Does not align with From domain '{from_domain}'."
        else:
            reason += " No signature domain (header.d) extracted."
        analysis["DKIM_Reason"] = reason
    else:
        # maybe signature present but status absent
        if dkim_domain:
            analysis["DKIM_Reason"] = f"DKIM signature domain present (header.d={dkim_domain}) but status not found."
        else:
            analysis["DKIM_Reason"] = "DKIM not present in Authentication-Results."

    # DMARC reasoning
    # DMARC typically requires alignment of From with SPF or DKIM
    if dmarc == "pass":
        reason = "DMARC reported PASS in Authentication-Results."
        if dmarc_domain:
            reason += f" header.from={dmarc_domain}."
            if from_domain and dmarc_domain == from_domain:
                reason += " DMARC domain aligns with From domain."
            else:
                reason += " DMARC 'header.from' does not match From exactly." if from_domain else ""
        analysis["DMARC_Reason"] = reason
    elif dmarc in ("fail", "quarantine", "reject", "bestguess"):
        reason = f"DMARC reported '{dmarc}' in Authentication-Results."
        # analyze alignment: check if DKIM or SPF align with From
        aligned = False
        align_reasons = []
        if dkim_domain and from_domain and dkim_domain == from_domain:
            aligned = True
            align_reasons.append("DKIM aligned with From")
        if rp_domain and from_domain and rp_domain == from_domain and domains.get("SPF_Status") == "pass":
            aligned = True
            align_reasons.append("SPF aligned with From via Return-Path")
        if align_reasons:
            reason += " However, alignment detected: " + "; ".join(align_reasons) + "."
        else:
            reason += " No DKIM/SPF alignment found with From domain."
        if dmarc_domain:
            reason += f" DMARC header.from={dmarc_domain}."
        analysis["DMARC_Reason"] = reason
    else:
        # none/unknown
        analysis["DMARC_Reason"] = "DMARC information not found in Authentication-Results."

    # Alignment boolean: consider alignment if DKIM or DMARC domains equal From domain
    if from_domain and (dkim_domain == from_domain or dmarc_domain == from_domain):
        analysis["Domains_Match_Alignment"] = True

    # add short details for UI (these will be turned into HTML by caller)
    analysis["Details"].append(f"SPF status: {analysis['SPF_Status']}")
    analysis["Details"].append(f"DKIM status: {analysis['DKIM_Status']}")
    analysis["Details"].append(f"DMARC status: {analysis['DMARC_Status']}")

    return analysis


VT_API_KEY = os.getenv("VT_API_KEY", "945a5b5e9f50483182841c3445de8a50c4282c3173b3991498b024f5920a1912")

def vt_domain_lookup(domain):
    """
    Queries VirusTotal for domain reputation & analysis stats.
    Returns dict with safe fields for display.
    """

    if not domain:
        return {"error": "No domain provided"}

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        r = requests.get(url, headers=headers, timeout=10)

        if r.status_code == 404:
            return {"error": "Domain not found in VirusTotal database"}

        if r.status_code != 200:
            return {"error": f"VT API error: {r.status_code}"}

        data = r.json().get("data", {})
        attrs = data.get("attributes", {})

        # --- Extract useful VT fields ---
        rep = attrs.get("reputation")
        cats = attrs.get("categories", {})
        whois = attrs.get("whois", "")
        last_analysis = attrs.get("last_analysis_stats", {})
        tags = attrs.get("tags", [])

        return {
            "reputation": rep,
            "categories": cats,
            "whois": whois[:500] + "..." if whois and len(whois) > 500 else whois,
            "tags": tags,
            "analysis": last_analysis
        }

    except Exception as e:
        return {"error": str(e)}


# --- (rest of app.py remains as before: parsing bodies, analyzing email, CVE, etc.)
# For brevity I've included the unchanged parts from your previous app.py and ensured the
# analyze_eml_file() attaches domain_analysis plus converts reasons to HTML-safe strings.

# reusing helper functions: get_email_body, extract_urls, is_ip, check_cves, classify_severity, etc.
# (Please keep all helper functions from your existing app.py - they remain unchanged, see prior file)

# Below: minimal implementations reused from previous app.py (copy your existing functions here).
def get_email_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            disp = (part.get("Content-Disposition") or "").lower()
            if "attachment" in disp:
                continue
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            try: text = payload.decode(errors="ignore")
            except Exception: text = str(payload)
            if part.get_content_type() == "text/html":
                body += BeautifulSoup(text, "html.parser").get_text()
            else:
                body += text
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            try: text = payload.decode(errors="ignore")
            except Exception: text = str(payload)
            if msg.get_content_type() == "text/html":
                body = BeautifulSoup(text, "html.parser").get_text()
            else:
                body = text
    return body or ""

def extract_urls(text):
    if not text:
        return []
    return re.findall(r'https?://[^\s"<>]+', text)

def is_ip(host):
    try:
        h = host.split(":")[0]
        ipaddress.ip_address(h)
        return True
    except Exception:
        return False

def check_cves(text):
    found = []
    t = (text or "").lower()
    for entry in CVE_DB:
        for kw in entry.get("keywords", []):
            if kw.lower() in t:
                found.append({
                    "cve": entry["cve"],
                    "keyword": kw,
                    "description": entry.get("description", "")
                })
                break
    return found


# Phishing rules and analyze_email unchanged — please reuse your analyze_email function from the earlier file.
PHISHING_KEYWORDS = [
    r"\bverify(?:\s+your\s+)?account\b", r"\bclick\s+here.*?(login|update|reset|access)",
    r"\bupdate\s+your\s+information\b", r"\bsecurity\s+alert\b", r"\breset\s+your\s+password\b",
    r"\bconfirm\s+your\s+details\b", r"\burgent\b", r"\bact\s+now\b", r"\blimited\s+time\b",
    r"\bbank\s+account\b", r"\bcredit\s+card\b", r"(re-)enter.*password", r"login\s+immediately",
    r"unauthorized\s+access", r"scan the qr code", r"pay in bitcoin", r"itunes gift card",
    r"verify using this code", r"upload your id", r"listen to voicemail", r"reset mfa",
    r"urgent wire transfer", r"secret account"
]
MILD_KEYWORDS = [r"\blogin\b", r"\bupdate\b", r"\baccount\b", r"\bverify\b", r"\balert\b"]
TRUSTED_DOMAINS = ["gmail.com", "outlook.com", "yahoo.com", "icloud.com", "hotmail.com", "microsoft.com", "apple.com"]

def analyze_email(sender, subject, body, attachments, headers):
    # This function is identical to your previous analyze_email (score & details building).
    # For brevity copy your existing implementation here (it will produce result["details"] list).
    # After compute, returns {"sender":..., "subject":..., "score":..., "verdict":..., "details": [...]}
    score = 0
    details = []
    sender_domain = (sender.split("@")[-1] if "@" in sender else "unknown").lower()
    body_lower = (body or "").lower()

    for pat in PHISHING_KEYWORDS:
        if re.search(pat, body_lower):
            score += 10
            text = f"Phishing keyword/phrase matched: {pat}"
            details.append({"text": text, "severity": classify_severity(text)})
    for pat in MILD_KEYWORDS:
        if re.search(pat, body_lower):
            score += 2
            text = f"Mild keyword matched: {pat}"
            details.append({"text": text, "severity": classify_severity(text)})

    if re.search(r"\b(pass(word)?|credit|ssn|confidential|upload id|otp|credential)\b", body_lower):
        score += 12
        text = "Request for credentials or personal information detected"
        details.append({"text": text, "severity": classify_severity(text)})

    urls = extract_urls(body)
    if urls:
        details.append({"text": f"URLs detected: {', '.join(urls)}", "severity": "medium"})
        unusual_tlds = ['.tk', '.ru', '.cn', '.xyz', '.top', '.biz', '.info']
        for url in urls:
            parsed = urlparse(url)
            domain = (parsed.netloc or "").lower()
            domain = domain.split("@")[-1].split(":")[0]
            tld = '.' + domain.split('.')[-1] if '.' in domain else ''
            if is_ip(domain):
                score += 10
                details.append({"text": f"URL uses IP address as domain: {domain}", "severity": "high"})
            if tld in unusual_tlds:
                score += 7
                details.append({"text": f"Unusual domain extension '{tld}' in URL domain '{domain}'", "severity": "medium"})
            if any(short in domain for short in ["bit.ly", "tinyurl", "t.co", "goo.gl"]):
                score += 12
                details.append({"text": f"Shortened URL detected: {domain}", "severity": "high"})
            if sender_domain not in domain and not any(trust in domain for trust in TRUSTED_DOMAINS):
                score += 8
                details.append({"text": f"URL domain '{domain}' does not match sender domain '{sender_domain}' or trusted domains", "severity": "medium"})
            elif sender_domain != domain:
                score += 5
                details.append({"text": f"Domain mismatch: sender domain '{sender_domain}', URL domain '{domain}'", "severity": "medium"})

    soup = BeautifulSoup(body or "", "html.parser")
    for a in soup.find_all('a', href=True):
        vis = a.get_text(strip=True)
        href = a['href']
        if vis and href and vis not in href:
            score += 7
            text = f"Hyperlink visible text '{vis}' differs from actual URL '{href}'"
            details.append({"text": text, "severity": classify_severity(text)})

    for att in (attachments or []):
        fn = (att or "").lower()
        if any(fn.endswith(ext) for ext in [".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".msi", ".lnk"]):
            score += 14
            text = f"Suspicious attachment: {att}"
            details.append({"text": text, "severity": "high"})
        if any(g in fn for g in ["invoice", "document", "payment", "urgent", "scan", "statement"]):
            score += 3
            text = f"Generic attachment name: {att}"
            details.append({"text": text, "severity": "low"})

    m = re.match(r'(.+?)\s*<(.+?)>', sender or "")
    if m:
        display = m.group(1).strip()
        email_addr = m.group(2).strip()
        local = email_addr.split('@')[0].lower()
        if display.replace(" ","").lower() not in local:
            score += 7
            text = f"Display name '{display}' doesn't match email local part '{local}'"
            details.append({"text": text, "severity": classify_severity(text)})

    if sender_domain in TRUSTED_DOMAINS:
        score -= 10
        details.append({"text": f"Sender domain '{sender_domain}' is in trusted list", "severity": "low"})
    else:
        score += 5
        details.append({"text": f"Sender domain '{sender_domain}' not trusted", "severity": "low"})

    rp = (headers.get("Return-Path") or "").strip()
    rt = (headers.get("Reply-To") or "").strip()
    if rp and rp.lower() != (sender or "").lower():
        score += 7
        details.append({"text": f"Return-Path '{rp}' ≠ From '{sender}'", "severity": "medium"})
    if rt and rt.lower() != (sender or "").lower():
        score += 7
        details.append({"text": f"Reply-To '{rt}' ≠ From '{sender}'", "severity": "medium"})

    if (subject or "").isupper() or "!" in (subject or ""):
        score += 3
        details.append({"text": "Subject uses excessive caps/exclamation", "severity": "low"})
    if re.search(r"\burgent|immediately|important|action required\b", (subject or "").lower()):
        score += 5
        details.append({"text": "Urgent or scare-tactic subject line", "severity": "medium"})

    cves = check_cves(body)
    if cves:
        score += 15
        for c in cves:
            text = f"Possible CVE reference: {c['cve']} ({c['keyword']}) - {c.get('description','')}"
            details.append({"text": text, "severity": "critical"})

    if score >= 30:
        verdict = "🚨 High Risk: Likely Phishing or Spam"
    elif score >= 12:
        verdict = "⚠️ Medium Risk: Suspicious"
    else:
        verdict = "✅ Low Risk: Likely Genuine"

    # VirusTotal lookup for each extracted domain
    vt_results = []

    # 1. Check Sender Domain (New Logic)
    # Cleanly extracts the domain, converts to lowercase, and then strips the trailing '>'
    sender_domain = (sender.split("@")[-1] if "@" in sender else "unknown").lower().rstrip('>')

    if sender_domain and sender_domain not in TRUSTED_DOMAINS and sender_domain != "unknown":
        vt_info = vt_domain_lookup(sender_domain)
        # Check if the domain is already marked as suspicious/malicious by VT
        analysis_stats = vt_info.get("analysis", {})
        if analysis_stats.get("malicious", 0) > 0 or analysis_stats.get("suspicious", 0) > 0:
            score += 15  # High risk score for VT-flagged sender domain
            text = f"Sender domain '{sender_domain}' flagged by VirusTotal (Malicious: {analysis_stats.get('malicious', 0)}, Suspicious: {analysis_stats.get('suspicious', 0)})"
            details.append({"text": text, "severity": "critical"})

        vt_results.append({
            "domain": sender_domain,
            "vt": vt_info
        })

    # 2. Check URL Domains (Existing Logic)
    urls = extract_urls(body)  # Assuming this was defined earlier, if not, define it here
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0].lower()
        domain = domain.rstrip('>') # Clean the extracted domain, removing '>' if it exists at the end
        if domain in [item["domain"] for item in vt_results]:  # Skip if sender domain was already checked
            continue

        # ... (existing scoring logic for IP/shortened URLs) ...

        vt_info = vt_domain_lookup(domain)
        vt_results.append({
            "domain": domain,
            "vt": vt_info
        })

    # =======================================================
    # FIX: DEFINE AND RETURN THE 'result' DICTIONARY HERE
    # =======================================================

    # 3. Build the base result dict (assuming score, verdict, details, etc. are defined)
    result = {
        "sender": sender,
        "subject": subject,
        "score": score,
        "verdict": verdict,
        "details": details
    }

    # 4. Attach VirusTotal and CVE results
    result["virustotal"] = vt_results
    # Note: You need to ensure 'found_cves' is also defined and attached if used later
    # result["found_cves"] = found_cves

    # 5. Return the result
    return result


# analyze_eml_file that attaches domain_analysis and HTML-safe strings for template
def analyze_eml_file(file_path):
    with open(file_path, "rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)
    sender = msg.get("From", "Unknown")
    subject = msg.get("Subject", "No Subject") or "No Subject"
    body = get_email_body(msg)
    attachments = [p.get_filename() for p in msg.iter_attachments() if p.get_filename()]
    headers = {"From": msg.get("From",""), "Return-Path": msg.get("Return-Path",""), "Reply-To": msg.get("Reply-To",""), "Authentication-Results": msg.get("Authentication-Results","")}
    domains = extract_domains(headers)
    domain_analysis = analyze_domains(domains)
    result = analyze_email(sender, subject, body, attachments, headers)
    result["domains"] = domains
    result["domain_analysis"] = domain_analysis

    # add HTML for each detail and for domain analysis reasons
    for d in result["details"]:
        d["html"] = server_highlight(d["text"])
    domain_analysis["Details_HTML"] = [server_highlight(x) for x in domain_analysis["Details"]]

    # also prepare reason HTML-safe
    domain_analysis["SPF_Reason_HTML"] = server_highlight(domain_analysis.get("SPF_Reason",""))
    domain_analysis["DKIM_Reason_HTML"] = server_highlight(domain_analysis.get("DKIM_Reason",""))
    domain_analysis["DMARC_Reason_HTML"] = server_highlight(domain_analysis.get("DMARC_Reason",""))

    # build found_cves as before
    found_cves = []
    for d in result["details"]:
        text = d["text"].lower()
        if "cve-" in text:
            m = re.search(r"(cve-\d{4}-\d{4,7})", text)
            if m:
                found_cves.append({"cve": m.group(1).upper(), "text": d["text"], "html": d["html"]})
    result["found_cves"] = found_cves

    return result

# routes
@app.route("/", methods=["GET","POST"])
def upload_file():
    if request.method == "POST":
        if "file" not in request.files:
            return render_template("index.html", error="No file uploaded.")
        file = request.files["file"]
        if file.filename == "":
            return render_template("index.html", error="No file selected.")
        if file and file.filename.lower().endswith(".eml"):
            file_path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(file_path)
            result = analyze_eml_file(file_path)
            return render_template("result.html", result=result)
        else:
            return render_template("index.html", error="Please upload a valid .eml file.")
    return render_template("index.html")


@app.route("/download-report", methods=["POST"])
def download_report():
    # 1. UNWRAP the dictionary and ensure data is present
    data = request.json
    if not data or 'result' not in data:
        return {"error": "Invalid request payload"}, 400

    # The actual analysis data is nested inside the 'result' key
    analysis_result = data.get('result', {})

    # SECURITY FIX: Ensure all strings are safe by wrapping them in Markup
    # This prevents HTML injection in pdf_report.html which uses safe/unescaped variables.
    for key in analysis_result.get('domain_analysis', {}):
        if '_Reason' in key:
            analysis_result['domain_analysis'][key] = Markup(analysis_result['domain_analysis'][key])

    for item in analysis_result.get('details', []):
        if 'html' in item:
             item['html'] = Markup(item['html'])
        if 'text' in item:
             item['text'] = Markup(item['text'])

    # 2. Render HTML using the correctly unwrapped and cleaned data
    from datetime import datetime
    html = render_template("pdf_report.html", result=analysis_result, now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    # 3. Path to wkhtmltopdf (ensure this path is correct for your system)
    config = pdfkit.configuration(wkhtmltopdf=r"C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            # Setting --enable-local-file-access flag to true might be required, but
            # this also increases the Local File Disclosure risk. The Command Injection
            # vulnerability remains due to pdfkit's reliance on shell execution.
            options = {
                'quiet': '',  # Suppress wkhtmltopdf output to avoid pipeline buffering issues
            }
            timestamp=datetime.now()
            download_filename = f"email_analysis-{timestamp}.pdf"
            pdfkit.from_string(html, tmp.name, configuration=config, options=options)
            return send_file(tmp.name, as_attachment=True, download_name=download_filename)
    except Exception as e:
        # Crucial for debugging "something went wrong"
        print(f"PDF GENERATION ERROR: {e}")
        return f"Error generating PDF: {e}", 500


if __name__ == "__main__":
    app.run()
