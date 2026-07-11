import streamlit as st
import numpy as np
import joblib
import socket
import pandas as pd
import re
import base64
import ssl
import time
from urllib.parse import urlparse, unquote
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from pathlib import Path
from tensorflow.keras.models import load_model
import pefile
from utils.file_threat_detector import SUPPORTED_EXTENSIONS, analyze_file
from utils.ui_shell import render_sidebar

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="Auto Threat Scan",
    layout="wide",
    page_icon="🌐"
)

# ---------------- AUTH ----------------
if "authenticated" not in st.session_state or not st.session_state.authenticated:
    st.switch_page("app.py")

DEFAULT_SUSPICIOUS_TEXT_PATTERNS = [
    "eicar",
    "malware",
    "virus",
    "trojan",
    "worm",
    "ransomware",
    "spyware",
    "keylogger",
    "payload",
    "shellcode",
    "backdoor",
    "botnet",
    "phishing",
    "encrypt all files",
    "steal password",
    "cmd.exe",
    "powershell -enc",
    "hacked",
    "attack",
    "threat",
]


def load_suspicious_text_patterns():
    pattern_file = Path("text_scan_reference") / "suspicious_text_list.txt"
    if pattern_file.exists():
        patterns = [
            line.strip().lower()
            for line in pattern_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if patterns:
            return patterns
    return DEFAULT_SUSPICIOUS_TEXT_PATTERNS


# ---------------- BACKGROUND IMAGE ----------------
def add_bg(image_file):

    with open(image_file, "rb") as img:
        encoded = base64.b64encode(img.read()).decode()

    st.markdown(
        f"""
        <style>

        .stApp {{
            background-image: url("data:image/jpg;base64,{encoded}");
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
        }}

        /* Dark Overlay */
        .stApp::before {{
            content:"";
            position:fixed;
            top:0;
            left:0;
            width:100%;
            height:100%;
            background:rgba(0,0,0,0.75);
            z-index:-1;
        }}

        /* Title Glow */
        .main-title {{
            text-align:center;
            font-size:40px;
            font-weight:bold;
            color:#00ffe0;
            text-shadow:0 0 20px #00ffe0;
        }}

        </style>
        """,
        unsafe_allow_html=True
    )

# Background image path
add_bg("assets/3607424.jpg")
render_sidebar(show_logout=True)

st.markdown("""
<style>
.block-container {
    padding-top: 1.8rem;
    padding-bottom: 1.2rem;
    max-width: 1120px;
}

.stApp::before {
    background:
        radial-gradient(circle at top, rgba(88, 216, 255, 0.10), transparent 28%),
        linear-gradient(180deg, rgba(2, 8, 15, 0.22), rgba(4, 13, 22, 0.68)) !important;
}

.main-title {
    font-size: 2.3rem !important;
    font-weight: 700 !important;
    color: #eef8ff !important;
    text-shadow: none !important;
    margin-bottom: 0.25rem !important;
}

[data-testid="stTabs"] [role="tablist"] {
    gap: 0.65rem;
}

[data-testid="stTabs"] [role="tab"] {
    border-radius: 14px;
    padding: 0.6rem 1rem;
    background: rgba(7, 19, 29, 0.72);
    border: 1px solid rgba(96, 211, 255, 0.14);
    color: #d8f4ff;
}

[data-testid="stTabs"] [aria-selected="true"] {
    background: rgba(88, 216, 255, 0.12);
    border-color: rgba(96, 211, 255, 0.32);
}

[data-testid="stTextInputRootElement"] > div,
[data-testid="stNumberInput"] > div > div,
[data-testid="stSelectbox"] > div > div,
[data-testid="stFileUploader"] section {
    background: rgba(3, 12, 19, 0.88) !important;
    border: 1px solid rgba(96, 211, 255, 0.18) !important;
    border-radius: 14px !important;
}

[data-testid="stFileUploaderDropzone"] button {
    max-width: 128px !important;
    min-width: 128px !important;
    padding: 0.45rem 0.8rem !important;
    margin-left: auto !important;
    margin-right: 0.3rem !important;
    font-size: 0.88rem !important;
}

[data-testid="stFileUploaderDropzoneInstructions"] > div {
    gap: 0.5rem !important;
}

[data-testid="stWidgetLabel"] {
    color: #eef8ff;
    font-weight: 600;
}

.stButton > button {
    min-height: 2.95rem;
    border-radius: 14px;
    border: 1px solid rgba(96, 211, 255, 0.22);
    background: linear-gradient(90deg, rgba(88, 216, 255, 0.96), rgba(123, 240, 207, 0.94));
    color: #06131d;
    font-size: 0.96rem;
    font-weight: 700;
    box-shadow: 0 12px 24px rgba(18, 148, 188, 0.22);
}

.stButton > button:hover {
    box-shadow: 0 16px 30px rgba(18, 148, 188, 0.28), 0 0 18px rgba(88, 216, 255, 0.14);
}

[data-testid="stAlert"] {
    border-radius: 16px;
    border: 1px solid rgba(255,255,255,0.08);
}

.scan-side-panel {
    min-height: 242px;
    padding: 0.9rem 0.95rem;
    border-radius: 18px;
    background: linear-gradient(180deg, rgba(5, 14, 23, 0.88), rgba(6, 16, 27, 0.76));
    border: 1px solid rgba(96, 211, 255, 0.16);
    box-shadow: 0 16px 34px rgba(0, 0, 0, 0.20);
}

.scan-side-panel h4 {
    margin: 0;
    color: #eef8ff;
    font-size: 1.05rem;
    font-weight: 700;
}

.scan-side-panel p {
    margin: 0.35rem 0 0.9rem 0;
    color: rgba(238, 248, 255, 0.68);
    font-size: 0.92rem;
    line-height: 1.5;
}

.scan-loader-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.65rem;
    padding: 0.55rem 0.9rem;
    border-radius: 999px;
    background: rgba(96, 211, 255, 0.10);
    border: 1px solid rgba(96, 211, 255, 0.16);
    color: #dff7ff;
    font-size: 0.92rem;
    font-weight: 700;
    letter-spacing: 0.03em;
}

.scan-loader-badge.done {
    background: rgba(64, 221, 160, 0.12);
    border-color: rgba(64, 221, 160, 0.22);
}

.scan-loader-ring {
    width: 16px;
    height: 16px;
    border-radius: 999px;
    background: #66dcff;
    animation: scanPulse 0.9s ease-in-out infinite;
}

.scan-loader-badge.done .scan-loader-ring {
    background: #40dda0;
    animation: none;
}

.scan-stage-card {
    margin-top: 0.8rem;
    padding: 0.82rem 0.9rem;
    border-radius: 16px;
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid rgba(96, 211, 255, 0.10);
}

.scan-stage-label {
    color: rgba(223, 247, 255, 0.68);
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 0.45rem;
}

.scan-stage-text {
    color: #eef8ff;
    font-size: 0.98rem;
    font-weight: 650;
    line-height: 1.45;
}

.scan-stage-note {
    margin-top: 0.7rem;
    color: rgba(238, 248, 255, 0.66);
    font-size: 0.9rem;
    line-height: 1.5;
}

@keyframes scanPulse {
    0% { box-shadow: 0 0 0 0 rgba(102, 220, 255, 0.44); transform: scale(1); }
    70% { box-shadow: 0 0 0 16px rgba(102, 220, 255, 0); transform: scale(1.15); }
    100% { box-shadow: 0 0 0 0 rgba(102, 220, 255, 0); transform: scale(1); }
}
</style>
""", unsafe_allow_html=True)


# ---------------- TITLE ----------------
st.markdown("<div class='main-title'>🌐 Cloud-Level Threat Intelligence Scanner</div>", unsafe_allow_html=True)


# ---------------- TITLE HELPERS ----------------
def show_scan_progress(step_messages, intro_text):
    progress_caption = st.caption(intro_text)
    status_line = st.empty()
    progress_bar = st.progress(0)

    total_steps = len(step_messages)
    for index, message in enumerate(step_messages, start=1):
        status_line.info(message)
        progress_bar.progress(int(index / total_steps * 100))
        time.sleep(0.22)

    status_line.success("Analysis complete. Preparing results.")
    time.sleep(0.12)
    progress_caption.empty()
    status_line.empty()
    progress_bar.empty()


def render_scan_status_panel(container, title, subtitle, step_text="", progress_value=0, completed=False, footer_text=""):
    badge_class = "scan-loader-badge done" if completed else "scan-loader-badge"
    badge_text = "Scan Completed" if completed else "Scanning in Progress"
    stage_label = "Final Status" if completed else "Current Stage"

    with container.container():
        st.markdown(
            f"""
            <div class="scan-side-panel">
                <h4>{title}</h4>
                <p>{subtitle}</p>
                <div class="{badge_class}">
                    <div class="scan-loader-ring"></div>
                    <span>{badge_text}</span>
                </div>
                <div class="scan-stage-card">
                    <div class="scan-stage-label">{stage_label}</div>
                    <div class="scan-stage-text">{step_text}</div>
                    <div class="scan-stage-note">{footer_text}</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.progress(progress_value)


# ---------------- SYSTEM IP DETECTION ----------------
hostname = socket.gethostname()
local_ip = socket.gethostbyname(hostname)

#st.info(f"🖥 System IP Detected: {local_ip}")


# ---------------- TABS ----------------
tab1, tab2, tab3 = st.tabs(["📁 File Scan", "🌐 URL Scan", "🛰 IP Scan"])


# =========================================================
# 📁 FILE SCAN (Malware Detection)
# =========================================================

with tab1:
    st.subheader("📁 Upload File for Threat Scan")
    st.caption("Supported formats: .exe, .pdf, .docx, .json")
    file_col, status_col = st.columns([1.55, 0.82], gap="large")
    file_steps = [
        "Validating the uploaded file type and header",
        "Extracting structural and security features",
        "Reviewing suspicious indicators and metadata",
        "Running the detection engine",
        "Preparing the final file verdict",
    ]

    with file_col:
        uploaded_file = st.file_uploader(
            "Upload file",
            type=list(SUPPORTED_EXTENSIONS),
        )

    with status_col:
        file_status_panel = st.empty()

    if uploaded_file:
        uploaded_file.seek(0)
        content = uploaded_file.read()
        result = None

        for index, step in enumerate(file_steps):
            render_scan_status_panel(
                file_status_panel,
                "Live File Scan",
                "The backend is actively processing the uploaded file now.",
                step_text=step,
                progress_value=int(((index + 1) / len(file_steps)) * 100),
                footer_text="Please wait while the scanner validates the file, extracts threat signals, and prepares the decision.",
            )

            if index == 2:
                result = analyze_file(uploaded_file.name, content)

            time.sleep(0.22)

        if result is None:
            result = analyze_file(uploaded_file.name, content)

        render_scan_status_panel(
            file_status_panel,
            "File Scan Completed",
            "The backend processing finished and the final risk output is now ready.",
            step_text=f"Final Result: {result['label']} ({result['risk']})",
            progress_value=100,
            completed=True,
            footer_text="The scan has completed successfully. You can now review the threat result and detailed file analysis below.",
        )

        st.info(
            "The file scanner checks the format, extracts security-related signals, runs the detection model, "
            "and then prepares the final risk decision."
        )

        st.markdown("### 📊 File Details")
        st.info(f"📦 File Size: {round(result['features']['size_bytes'] / (1024 * 1024), 4)} MB")
        st.info(f"🧾 Detected Type: {result['file_type'].upper()}")
        st.info(f"📈 File Complexity (Entropy): {round(result['features']['entropy'], 2)}")

        if result["risk"] == "HIGH":
            st.error("⚠ Threat Detected")
            st.markdown("### 🔴 Risk Level : HIGH")
            card_color = "#ff4b4b"
            card_title = "⚠ Threat Detected"
            card_message = "This file contains strong malicious indicators"
            card_risk = "🔴 Risk: HIGH"
        elif result["risk"] == "MEDIUM":
            st.warning("⚠ Suspicious File Pattern")
            st.markdown("### 🟠 Risk Level : MEDIUM")
            card_color = "#ff9800"
            card_title = "⚠ Review Recommended"
            card_message = "This file needs manual review before it is trusted"
            card_risk = "🟠 Risk: MEDIUM"
        else:
            st.success("✅ File Safe")
            st.markdown("### 🟢 Risk Level : LOW")
            card_color = "#00c853"
            card_title = "✅ File is Safe"
            card_message = "No strong malicious behavior was found"
            card_risk = "🟢 Risk: LOW"

        st.caption(
            f"Classification: {result['label']} | Confidence: {result['confidence']}%"
        )
        if result["model_probability"] is not None:
            st.caption(
                f"Model verdict: {result['model_prediction']} "
                f"({result['model_probability']}%)"
            )

        if result["reasons"]:
            st.markdown("### Suspicious Signals Found")
            for item in result["reasons"]:
                st.write(f"- {item}")
        else:
            st.info("No strong suspicious signals were found from the available checks.")

        details_df = pd.DataFrame(
            [{"Signal": key, "Value": value} for key, value in result["features"].items()]
        )
        st.dataframe(details_df, use_container_width=True, hide_index=True)

        st.markdown(
            f"""
            <div style='
                padding:15px;
                border-radius:10px;
                background:{card_color};
                color:white;
                max-width:420px;
                margin:auto;
                text-align:center;
                box-shadow:0 0 10px rgba(255,255,255,0.2);
            '>
                <h3>{card_title}</h3>
                <p style="font-size:14px;">{card_message}</p>
                <b>{card_risk}</b>
            </div>
            """,
            unsafe_allow_html=True,
        )

# =========================================================
# 🌐 URL SCAN (Phishing Detection)
# =========================================================


with tab2:

    st.subheader("URL Threat Detection")

    url_input = st.text_input(
        "Enter URL to Scan",
        placeholder="Example: https://example.com"
    )

    def normalize_url(raw_url):
        cleaned = raw_url.strip()
        if not cleaned:
            return None, "Please enter a URL"

        # Support defanged samples copied from notes or reports.
        cleaned = re.sub(r"(?i)^hxxps://", "https://", cleaned)
        cleaned = re.sub(r"(?i)^hxxp://", "http://", cleaned)
        cleaned = cleaned.replace("[.]", ".").replace("(.)", ".")
        cleaned = cleaned.replace("[://]", "://")

        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
            cleaned = f"https://{cleaned}"

        parsed = urlparse(cleaned)
        if not parsed.netloc:
            return None, "Enter a valid URL or domain name"

        return parsed._replace(netloc=parsed.netloc.lower()).geturl(), None

    def get_host_parts(url):
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        labels = [part for part in hostname.split(".") if part]
        return parsed, hostname, labels

    def is_ip_host(hostname):
        return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname))

    def get_registered_domain(labels):
        if not labels:
            return ""
        if len(labels) >= 2:
            return ".".join(labels[-2:])
        return labels[0]

    def fetch_page(url):
        request = Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 ACLR URL Scanner"}
        )
        context = ssl.create_default_context()

        try:
            with urlopen(request, timeout=6, context=context) as response:
                return {
                    "body": response.read(250000).decode("utf-8", errors="ignore"),
                    "content_type": response.headers.get("Content-Type", ""),
                    "final_url": response.geturl(),
                    "status_code": getattr(response, "status", 200),
                    "error": None,
                }
        except HTTPError as exc:
            return {
                "body": "",
                "content_type": "",
                "final_url": url,
                "status_code": exc.code,
                "error": f"HTTP {exc.code}",
            }
        except URLError as exc:
            return {
                "body": "",
                "content_type": "",
                "final_url": url,
                "status_code": None,
                "error": str(exc.reason),
            }
        except Exception as exc:
            return {
                "body": "",
                "content_type": "",
                "final_url": url,
                "status_code": None,
                "error": str(exc),
            }

    def count_external_links(html, hostname):
        refs = re.findall(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", html, flags=re.IGNORECASE)
        total = 0
        external = 0

        for link in refs:
            if link.startswith(("javascript:", "#", "mailto:")):
                continue

            total += 1
            parsed_link = urlparse(link)
            link_host = parsed_link.hostname or ""

            if parsed_link.scheme in ("http", "https") and link_host and hostname not in link_host:
                external += 1

        return total, external

    def extract_features(url):
        parsed, hostname, labels = get_host_parts(url)
        shorteners = {
            "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "ow.ly",
            "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy"
        }
        suspicious_tlds = {
            "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click",
            "link", "live", "work", "support", "shop"
        }
        phishing_keywords = {
            "login", "signin", "sign-in", "verify", "verification",
            "password", "reset", "recover", "account", "secure",
            "wallet", "bank", "payment", "billing", "invoice", "ssn"
        }
        malware_keywords = {
            "download", "setup", "installer", "install", "update",
            "patch", "plugin", "extension", "crack", "keygen",
            "payload", "dropper", "loader", "invoice", "document",
            "attachment", "apk"
        }
        malware_extensions = (
            ".exe", ".msi", ".bat", ".cmd", ".scr", ".ps1", ".js",
            ".jar", ".vbs", ".zip", ".rar", ".7z", ".iso", ".img",
            ".dll", ".hta", ".apk"
        )
        deceptive_page_phrases = (
            "update your browser",
            "browser update required",
            "download now",
            "install now",
            "your pc is infected",
            "security alert",
            "urgent action required",
            "verify your account",
            "confirm your password"
        )
        brand_domains = {
            "paypal": {"paypal.com"},
            "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
            "office365": {"microsoft.com", "office.com", "office365.com"},
            "google": {"google.com"},
            "gmail": {"google.com", "gmail.com"},
            "apple": {"apple.com", "icloud.com"},
            "icloud": {"apple.com", "icloud.com"},
            "amazon": {"amazon.com"},
            "netflix": {"netflix.com"},
            "docusign": {"docusign.com"},
            "adobe": {"adobe.com"},
            "whatsapp": {"whatsapp.com"},
            "telegram": {"telegram.org"},
            "bankofamerica": {"bankofamerica.com"},
            "chase": {"chase.com"},
        }

        page = fetch_page(url)
        final_url = page["final_url"] or url
        final_parsed, final_hostname, final_labels = get_host_parts(final_url)
        html = page["body"]
        html_lower = html.lower() if html else ""

        external_total, external_count = count_external_links(html, final_hostname) if html else (0, 0)
        anchor_links = re.findall(r"""<a\b[^>]*href\s*=\s*["']([^"']*)["']""", html, flags=re.IGNORECASE)
        total_anchors = len(anchor_links)
        unsafe_anchors = sum(
            1 for link in anchor_links
            if link.strip().lower() in ("", "#", "javascript:void(0)", "javascript:;", "#content", "#skip")
        )
        anchor_ratio = (unsafe_anchors / total_anchors) if total_anchors else 0

        form_actions = re.findall(r"""<form\b[^>]*action\s*=\s*["']([^"']*)["']""", html, flags=re.IGNORECASE)
        has_mailto = bool(re.search(r"mailto:", html, flags=re.IGNORECASE))
        has_iframe = bool(re.search(r"<iframe\b", html, flags=re.IGNORECASE))
        has_mouseover = bool(re.search(r"onmouseover\s*=", html, flags=re.IGNORECASE))
        has_right_click_block = bool(re.search(r"event\.button\s*==\s*2|contextmenu", html, flags=re.IGNORECASE))
        has_popup = bool(re.search(r"window\.open\s*\(", html, flags=re.IGNORECASE))
        redirect_count = 1 if final_url.rstrip("/") != url.rstrip("/") else 0

        url_length = len(url)
        subdomain_count = max(len(final_labels) - 2, 0)
        has_dash = "-" in final_hostname
        contains_at = "@" in url
        has_double_slash_redirect = "//" in url[8:]
        suspicious_https_token = "https" in final_hostname.replace(".", "")
        suspicious_port = parsed.port is not None and parsed.port not in (80, 443)
        uses_shortener = any(final_hostname.endswith(domain) for domain in shorteners)
        has_ip = is_ip_host(final_hostname)
        registered_domain = get_registered_domain(final_labels)
        decoded_path = unquote(final_parsed.path or "")
        decoded_query = unquote(final_parsed.query or "")
        decoded_full = f"{decoded_path}?{decoded_query}" if decoded_query else decoded_path
        decoded_full_lower = decoded_full.lower()
        punycode_host = any(label.startswith("xn--") for label in final_labels)
        suspicious_tld = bool(final_labels and final_labels[-1] in suspicious_tlds)
        encoded_character_count = len(re.findall(r"%[0-9a-fA-F]{2}", final_url))
        executable_download = any(decoded_path.lower().endswith(ext) for ext in malware_extensions)
        credential_keyword_hits = sorted(
            keyword for keyword in phishing_keywords
            if keyword in final_hostname or keyword in decoded_full_lower
        )
        malware_keyword_hits = sorted(
            keyword for keyword in malware_keywords
            if keyword in final_hostname or keyword in decoded_full_lower
        )
        redirect_parameter = bool(re.search(
            r"(?:[?&](?:url|redirect|redir|next|target|dest|destination)=)"
            r"(?:https?://|https?%3a%2f%2f)",
            final_url,
            flags=re.IGNORECASE
        ))
        digit_count = sum(1 for char in final_hostname if char.isdigit())
        heavy_digit_host = digit_count >= 6
        deceptive_page_content = any(phrase in html_lower for phrase in deceptive_page_phrases)
        has_password_field = bool(re.search(r"""type\s*=\s*["']password["']""", html_lower))
        obfuscated_script = bool(re.search(r"fromcharcode|unescape\s*\(|atob\s*\(", html_lower))

        impersonated_brands = []
        for brand, legitimate_domains in brand_domains.items():
            if brand in final_hostname or brand in decoded_full_lower:
                if not any(registered_domain.endswith(domain) for domain in legitimate_domains):
                    impersonated_brands.append(brand)

        if url_length < 54:
            url_length_feature = 1
        elif url_length <= 75:
            url_length_feature = 0
        else:
            url_length_feature = -1

        if subdomain_count <= 1:
            subdomain_feature = 1
        elif subdomain_count == 2:
            subdomain_feature = 0
        else:
            subdomain_feature = -1

        ssl_feature = 1 if final_parsed.scheme == "https" else -1

        if external_total == 0:
            request_url_feature = 0
            links_in_tags_feature = 0
        else:
            external_ratio = external_count / external_total
            request_url_feature = 1 if external_ratio < 0.22 else 0 if external_ratio <= 0.61 else -1
            links_in_tags_feature = 1 if external_ratio < 0.17 else 0 if external_ratio <= 0.81 else -1

        if anchor_ratio < 0.31:
            anchor_feature = 1
        elif anchor_ratio <= 0.67:
            anchor_feature = 0
        else:
            anchor_feature = -1

        if not form_actions:
            sfh_feature = 0
        else:
            suspicious_actions = 0
            for action in form_actions:
                lowered = action.strip().lower()
                if lowered in ("", "about:blank") or lowered.startswith(("mailto:", "javascript:")):
                    suspicious_actions += 1
            sfh_feature = -1 if suspicious_actions else 1

        features = [
            -1 if has_ip else 1,
            url_length_feature,
            -1 if uses_shortener else 1,
            -1 if contains_at else 1,
            -1 if has_double_slash_redirect else 1,
            -1 if has_dash else 1,
            subdomain_feature,
            ssl_feature,
            0,
            0,
            -1 if suspicious_port else 1,
            -1 if suspicious_https_token else 1,
            request_url_feature,
            anchor_feature,
            links_in_tags_feature,
            sfh_feature,
            -1 if has_mailto else 1,
            0,
            redirect_count,
            -1 if has_mouseover else 1,
            -1 if has_right_click_block else 1,
            -1 if has_popup else 1,
            -1 if has_iframe else 1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]

        signal_rows = {
            "Normalized URL": url,
            "Final URL": final_url,
            "Host": final_hostname,
            "Registered domain": registered_domain or "Unknown",
            "Scheme": final_parsed.scheme or parsed.scheme,
            "URL length": url_length,
            "Subdomain count": subdomain_count,
            "Has IP in host": has_ip,
            "Uses shortener": uses_shortener,
            "Punycode host": punycode_host,
            "Suspicious TLD": suspicious_tld,
            "Contains @": contains_at,
            "Redirected": bool(redirect_count),
            "Redirect parameter": redirect_parameter,
            "Executable/archive path": executable_download,
            "Encoded characters": encoded_character_count,
            "External resources": external_count,
            "Total resources": external_total,
            "Unsafe anchor ratio": round(anchor_ratio, 2),
            "Credential keywords": ", ".join(credential_keyword_hits[:5]) or "None",
            "Malware keywords": ", ".join(malware_keyword_hits[:5]) or "None",
            "Impersonated brands": ", ".join(impersonated_brands[:5]) or "None",
            "Fetch error": page["error"] or "None",
        }

        suspicious_signals = []
        if has_ip:
            suspicious_signals.append("URL uses an IP address instead of a domain")
        if uses_shortener:
            suspicious_signals.append("URL uses a shortening service")
        if contains_at:
            suspicious_signals.append("URL contains '@'")
        if has_double_slash_redirect:
            suspicious_signals.append("URL contains a double-slash redirect pattern")
        if punycode_host:
            suspicious_signals.append("Hostname uses punycode/IDN encoding")
        if has_dash:
            suspicious_signals.append("Hostname contains '-'")
        if subdomain_count >= 2:
            suspicious_signals.append("URL has multiple subdomains")
        if suspicious_tld:
            suspicious_signals.append("URL uses a commonly abused TLD")
        if final_parsed.scheme != "https":
            suspicious_signals.append("URL is not using HTTPS")
        if redirect_count:
            suspicious_signals.append("URL redirected to a different destination")
        if redirect_parameter:
            suspicious_signals.append("URL contains a redirect parameter")
        if impersonated_brands:
            suspicious_signals.append(
                f"URL appears to impersonate trusted brands: {', '.join(impersonated_brands[:3])}"
            )
        if credential_keyword_hits:
            suspicious_signals.append("URL contains credential or account-related lure keywords")
        if malware_keyword_hits:
            suspicious_signals.append("URL contains download or installer-related lure keywords")
        if executable_download:
            suspicious_signals.append("URL points directly to an executable or archive-like file")
        if heavy_digit_host:
            suspicious_signals.append("Hostname contains an unusual number of digits")
        if has_mailto:
            suspicious_signals.append("Page contains a mail submission pattern")
        if has_iframe:
            suspicious_signals.append("Page contains an iframe")
        if has_right_click_block:
            suspicious_signals.append("Page attempts to block right click")
        if has_popup:
            suspicious_signals.append("Page opens popup windows")
        if has_password_field:
            suspicious_signals.append("Page contains a password field")
        if deceptive_page_content:
            suspicious_signals.append("Page contains deceptive urgency or fake update wording")
        if obfuscated_script:
            suspicious_signals.append("Page contains obfuscated script patterns")

        phishing_score = 0
        malware_score = 0

        if has_ip:
            phishing_score += 3
            malware_score += 2
        if uses_shortener:
            phishing_score += 2
            malware_score += 1
        if contains_at:
            phishing_score += 2
        if has_double_slash_redirect:
            phishing_score += 2
        if punycode_host:
            phishing_score += 3
        if suspicious_tld:
            phishing_score += 1
            malware_score += 1
        if subdomain_count >= 2:
            phishing_score += 1
        if redirect_count:
            phishing_score += 1
            malware_score += 1
        if redirect_parameter:
            phishing_score += 2
        if impersonated_brands:
            phishing_score += 4
        if credential_keyword_hits:
            phishing_score += min(3, len(credential_keyword_hits))
        if has_password_field:
            phishing_score += 2
        if executable_download:
            malware_score += 5
        if malware_keyword_hits:
            malware_score += min(3, len(malware_keyword_hits))
        if deceptive_page_content:
            phishing_score += 1
            malware_score += 2
        if obfuscated_script:
            malware_score += 2
        if heavy_digit_host:
            malware_score += 1
        if has_iframe or has_popup:
            malware_score += 1

        analysis = {
            "phishing_score": phishing_score,
            "malware_score": malware_score,
            "combined_score": phishing_score + malware_score,
            "impersonated_brands": impersonated_brands,
            "executable_download": executable_download,
        }

        return features, signal_rows, suspicious_signals, page, analysis

    if st.button("Scan URL"):

        if url_input == "":
            st.warning("Please enter a URL")

        else:
            _, url_center_col, _ = st.columns([0.12, 0.76, 0.12])
            with url_center_col:
                url_status_panel = st.empty()

            url_steps = [
                "Normalizing and validating the URL",
                "Extracting URL structure features",
                "Inspecting redirects and suspicious content",
                "Running the phishing and malware classifier",
                "Preparing the final URL verdict",
            ]

            render_scan_status_panel(
                url_status_panel,
                "Live URL Scan",
                "The URL scanner is now working in the background.",
                step_text=url_steps[0],
                progress_value=20,
                footer_text="Please wait while the system validates the link and checks the security signals.",
            )
            time.sleep(0.22)

            normalized_url, validation_error = normalize_url(url_input)

            if validation_error:
                render_scan_status_panel(
                    url_status_panel,
                    "URL Scan Stopped",
                    "The URL could not be validated.",
                    step_text=validation_error,
                    progress_value=0,
                    completed=True,
                    footer_text="Enter a valid URL and run the scan again.",
                )
                st.error(validation_error)
            else:
                render_scan_status_panel(
                    url_status_panel,
                    "Live URL Scan",
                    "The scanner is extracting structural and redirect-based URL features.",
                    step_text=url_steps[1],
                    progress_value=45,
                    footer_text="The backend is now checking the URL pattern, host, redirects, and content indicators.",
                )
                features, signal_rows, suspicious_signals, page, analysis = extract_features(normalized_url)
                features = np.array(features).reshape(1, 30)

                render_scan_status_panel(
                    url_status_panel,
                    "Live URL Scan",
                    "The scanner is preparing the model prediction for this URL.",
                    step_text=url_steps[3],
                    progress_value=78,
                    footer_text="Machine learning and heuristic scoring are being combined for the final verdict.",
                )
                time.sleep(0.22)

                model = joblib.load("models/url_model.pkl")
                prediction = model.predict(features)[0]
                probability_map = {
                    cls: prob for cls, prob in zip(model.classes_, model.predict_proba(features)[0])
                }

                model_confidence = probability_map.get(prediction, 0) * 100
                model_flagged_phishing = prediction == -1
                phishing_score = analysis["phishing_score"]
                malware_score = analysis["malware_score"]
                combined_score = analysis["combined_score"]

                final_label = "Legitimate Website"
                risk = "LOW RISK"
                result_message = "Legitimate Website"

                if (
                    malware_score >= 5
                    or (analysis["executable_download"] and malware_score >= 4)
                    or (malware_score >= 4 and model_flagged_phishing)
                ):
                    final_label = "Malicious / Malware URL"
                    risk = "HIGH RISK"
                    result_message = "Malware / Malicious URL Detected"
                elif (
                    phishing_score >= 5
                    or (model_flagged_phishing and (phishing_score >= 3 or combined_score >= 5))
                    or (analysis["impersonated_brands"] and phishing_score >= 4)
                ):
                    final_label = "Phishing / Deceptive Website"
                    risk = "HIGH RISK"
                    result_message = "Phishing / Malicious Website Detected"
                elif model_flagged_phishing and model_confidence >= 65:
                    final_label = "Phishing / Deceptive Website"
                    risk = "HIGH RISK"
                    result_message = "Phishing / Malicious Website Detected"
                elif model_flagged_phishing and model_confidence >= 55:
                    final_label = "Suspicious URL"
                    risk = "MEDIUM RISK"
                    result_message = "Suspicious URL Detected"
                elif combined_score >= 4:
                    final_label = "Suspicious URL"
                    risk = "MEDIUM RISK"
                    result_message = "Suspicious URL Detected"

                confidence = max(model_confidence, min(99.0, 40 + (combined_score * 10)))

                render_scan_status_panel(
                    url_status_panel,
                    "URL Scan Completed",
                    "The URL analysis finished successfully.",
                    step_text=f"Final Result: {final_label} ({risk})",
                    progress_value=100,
                    completed=True,
                    footer_text="The complete URL result is ready below with confidence, signals, and analysis details.",
                )

                if risk == "HIGH RISK":
                    st.error(result_message)
                elif risk == "MEDIUM RISK":
                    st.warning(result_message)
                else:
                    st.success(result_message)

                st.write("### Detected Status:", risk)
                st.write("### Classification:", final_label)
                st.write("### Confidence Score:", round(confidence, 2), "%")
                st.caption(
                    f"Model verdict: {'Phishing' if model_flagged_phishing else 'Legitimate'} "
                    f"({round(model_confidence, 2)}%) | "
                    f"Heuristic scores -> phishing: {phishing_score}, malware: {malware_score}"
                )

                if suspicious_signals:
                    st.markdown("### Suspicious Signals Found")
                    for item in suspicious_signals:
                        st.write(f"- {item}")
                else:
                    st.info("No strong phishing signals were found from the available checks.")

                details_df = pd.DataFrame(
                    [{"Signal": key, "Value": value} for key, value in signal_rows.items()]
                )
                st.markdown("### URL Analysis Details")
                st.dataframe(details_df, use_container_width=True, hide_index=True)

                if page["error"]:
                    st.warning(
                        "Some live webpage checks could not be completed, so this result relied more on URL structure. "
                        f"Fetch result: {page['error']}"
                    )

# =========================================================
# 🛰 IP SCAN (IP Threat Detection)
# =========================================================

with tab3:

    st.subheader("🌍 IP Threat Detection")
    st.caption(
        "This model predicts IP threat level from behavior metrics, not from the IP address digits alone."
    )

    ip_reference = st.text_input(
        "IP Address (Optional Reference)",
        placeholder="Example: 192.168.1.10"
    )

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        ip_reputation_score = st.number_input(
            "IP Reputation Score",
            min_value=0,
            max_value=100,
            value=50,
            step=1,
            help="Lower score usually means worse reputation."
        )

    with col2:
        connection_rate = st.number_input(
            "Connection Rate",
            min_value=0,
            value=100,
            step=1,
            help="Number of connection attempts or traffic rate."
        )

    with col3:
        failed_login_attempts = st.number_input(
            "Failed Login Attempts",
            min_value=0,
            value=0,
            step=1
        )

    with col4:
        avg_packet_size = st.number_input(
            "Average Packet Size",
            min_value=0,
            value=500,
            step=1
        )

    with col5:
        unusual_port_access = st.selectbox(
            "Unusual Port Access",
            options=[0, 1],
            format_func=lambda x: "Yes" if x == 1 else "No"
        )

    if st.button("Scan IP"):
        _, ip_center_col, _ = st.columns([0.12, 0.76, 0.12])
        with ip_center_col:
            ip_status_panel = st.empty()

        ip_steps = [
            "Validating the IP behavior input",
            "Loading the IP reference dataset",
            "Comparing the input with known behavior patterns",
            "Calculating confidence and threat class",
            "Preparing the final IP result",
        ]

        render_scan_status_panel(
            ip_status_panel,
            "Live IP Scan",
            "The IP behavior scanner is now working in the background.",
            step_text=ip_steps[0],
            progress_value=18,
            footer_text="Please wait while the system validates the behavior values and compares them with known patterns.",
        )
        time.sleep(0.22)
        features = [[
            ip_reputation_score,
            connection_rate,
            failed_login_attempts,
            avg_packet_size,
            unusual_port_access
        ]]
        ip_df = pd.read_csv("dataset/ip_threat_detection_dataset.csv")
        render_scan_status_panel(
            ip_status_panel,
            "Live IP Scan",
            "The IP scanner is comparing your input with the reference dataset.",
            step_text=ip_steps[2],
            progress_value=56,
            footer_text="The backend is matching the values with known normal and suspicious behavior patterns.",
        )
        feature_cols = [
            "ip_reputation_score",
            "connection_rate",
            "failed_login_attempts",
            "avg_packet_size",
            "unusual_port_access",
        ]

        X = ip_df[feature_cols].astype(float)
        y = ip_df["label"].astype(str)
        input_vector = np.array(features[0], dtype=float)

        feature_range = (X.max() - X.min()).replace(0, 1)
        normalized_diff = (X - input_vector) / feature_range
        distances = np.sqrt((normalized_diff ** 2).sum(axis=1))

        nearest_count = 7
        nearest_idx = distances.nsmallest(nearest_count).index
        nearest_rows = ip_df.loc[nearest_idx].copy()
        nearest_rows["distance"] = distances.loc[nearest_idx].values
        nearest_rows["weight"] = 1 / (nearest_rows["distance"] + 1e-6)

        class_scores = nearest_rows.groupby("label")["weight"].sum().sort_values(ascending=False)
        prediction = class_scores.index[0]
        probability_text = round((class_scores.iloc[0] / class_scores.sum()) * 100, 2)

        render_scan_status_panel(
            ip_status_panel,
            "IP Scan Completed",
            "The IP analysis finished successfully.",
            step_text=f"Final Result: {prediction}",
            progress_value=100,
            completed=True,
            footer_text=f"The final IP risk result is ready below with confidence {probability_text}%.",
        )

        if prediction == "Normal":
            st.success("✅ Normal IP Behavior Detected")
            risk_level = "🟢 LOW"
        elif prediction in ("Botnet", "Malicious"):
            st.error(f"⚠ Threat Detected: {prediction}")
            risk_level = "🔴 HIGH"
        else:
            st.warning(f"⚠ Suspicious IP Behavior Detected: {prediction}")
            risk_level = "🟠 MEDIUM"

        st.markdown(f"### Detected Class: **{prediction}**")
        st.markdown(f"### Risk Level: **{risk_level}**")
        st.markdown(f"### Confidence Score: **{probability_text}%**")

        if ip_reference.strip():
            st.caption(f"Reference IP: {ip_reference.strip()}")

        details_df = pd.DataFrame([
            {"Feature": "IP Reputation Score", "Value": ip_reputation_score},
            {"Feature": "Connection Rate", "Value": connection_rate},
            {"Feature": "Failed Login Attempts", "Value": failed_login_attempts},
            {"Feature": "Average Packet Size", "Value": avg_packet_size},
            {"Feature": "Unusual Port Access", "Value": unusual_port_access},
        ])
        st.markdown("### Input Features Used For Prediction")
        st.dataframe(details_df, use_container_width=True, hide_index=True)

        nearest_display = nearest_rows[feature_cols + ["label"]].copy()
        st.markdown("### Most Similar Records From Dataset")
        st.dataframe(nearest_display, use_container_width=True, hide_index=True)

