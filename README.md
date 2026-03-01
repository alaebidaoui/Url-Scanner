URL SCANNER🔗

URL Scanner is a simple, lightweight Python tool that helps you check whether a link is safe before you click it.
It uses the VirusTotal API to scan URLs across 90+ antivirus engines and gives you an instant verdict.

Whether you're a developer, cybersecurity student, SOC analyst, or just someone who wants to avoid phishing traps — this tool makes link checking quick and easy

🔍 Features

Real-time URL scanning via VirusTotal (90+ antivirus engines)
Instant verdict: Malicious / Suspicious / Clean
Visual dashboard with scan results chart
Scan history saved locally
Simple and beginner-friendly interface (Streamlit)


⚙️ Installation

bashgit clone https://github.com/YOUR_USERNAME/url-scanner.git
cd url-scanner
pip install -r requirements.txt


🔧 Configuration

Create a .env file in the project folder:
VT_API_KEY="your_virustotal_api_key_here"
Get your free API key at virustotal.com


▶️ Usage

bashstreamlit run url_scanner.py
Open your browser at http://localhost:8501, enter any URL and click Scan.
🛡 Use Cases

Double-check suspicious links before clicking

Detect phishing URLs

Run quick checks during security investigations

Practice cybersecurity and threat analysis

Add a lightweight tool to your Blue Team toolkit


🗺 Roadmap

 WHOIS domain lookup
 Screenshot preview of scanned URL
 Bulk URL scanning (upload CSV)
 Export scan history as PDF
 Docker support


🧰 Tech Stack

Python
Streamlit
VirusTotal API v3

