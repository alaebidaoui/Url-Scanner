import os
import json
import base64
import datetime
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY   = os.getenv("VT_API_KEY")  # VirusTotal API key

HISTORY_FILE = "scan_history.json"


def encode_url(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode())
    return encoded.decode().strip("=")


def check_url(url: str) -> dict | None:
    headers = {"x-apikey": VT_API_KEY}
    url_id  = encode_url(url)
    response = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers=headers
    )
    if response.status_code == 200:
        data = response.json()
        return data["data"]["attributes"]["last_analysis_stats"]
    return None


def load_history() -> list:
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    return []


def save_to_history(url: str, stats: dict, verdict: str) -> None:
    history = load_history()
    history.append({
        "date"      : datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "url"       : url,
        "malicious" : stats["malicious"],
        "suspicious": stats["suspicious"],
        "harmless"  : stats["harmless"],
        "verdict"   : verdict  # "malicious" | "suspicious" | "clean"
    })
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


def get_verdict(stats: dict) -> str:
    if stats["malicious"] > 0:
        return "malicious"
    elif stats["suspicious"] > 0:
        return "suspicious"
    return "clean"


st.set_page_config(
    page_title="URL Scanner",
    page_icon="icon (1).png",
    layout="centered"
)

st.title("URL Scanner")
st.caption("Powered by VirusTotal")

url = st.text_input(
    "Enter a URL to scan",
    placeholder="https://example.com"
)

if st.button("Scan URL", type="primary"):
    if not url:
        st.warning("Please enter a URL.")
    else:
        with st.spinner("Scanning with VirusTotal..."):
            stats = check_url(url)

        if not stats:
            st.error("Failed to fetch data from VirusTotal. Check your API key.")
        else:
            verdict = get_verdict(stats)

            st.subheader("Scan Results")

            col1, col2, col3 = st.columns(3)
            col1.metric("🔴 Malicious",  stats["malicious"])
            col2.metric("🟡 Suspicious", stats["suspicious"])
            col3.metric("🟢 Harmless",   stats["harmless"])

            st.bar_chart({
                "Malicious" : [stats["malicious"]],
                "Suspicious": [stats["suspicious"]],
                "Harmless"  : [stats["harmless"]],
            })

            if verdict == "malicious":
                st.error("This URL is malicious!")
            elif verdict == "suspicious":
                st.warning("This URL looks suspicious.")
            else:
                st.success("This URL appears clean.")


            save_to_history(url, stats, verdict)

st.divider()
st.subheader("Scan History")

history = load_history()

if not history:
    st.caption("No scans yet. Run your first scan above!")
else:
    for entry in reversed(history):
        icon = {"malicious": "🔴", "suspicious": "🟡", "clean": "🟢"}.get(entry["verdict"], "⚪")

        with st.expander(f"{icon} {entry['url']}  —  {entry['date']}"):
            st.write(f"**Verdict:** `{entry['verdict']}`")
            st.write(f"Malicious: **{entry['malicious']}** | Suspicious: **{entry['suspicious']}** | Harmless: **{entry['harmless']}**")

    if st.button("🗑️Clear history"):
        os.remove(HISTORY_FILE)
        st.rerun()