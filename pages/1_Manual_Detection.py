import base64
import ipaddress
import joblib
import matplotlib.pyplot as plt
import numpy as np
import plotly.graph_objects as go
import streamlit as st
from tensorflow.keras.models import load_model
from utils.ui_shell import render_sidebar

# ---------------- AUTH ----------------
if "authenticated" not in st.session_state or not st.session_state.authenticated:
    st.switch_page("app.py")

st.set_page_config(page_title="Manual Detection", layout="wide")

# ---------------- BACKGROUND (CACHED) ----------------
@st.cache_data
def get_bg(image_file):
    with open(image_file, "rb") as img:
        return base64.b64encode(img.read()).decode()

def add_bg(image_file):
    encoded = get_bg(image_file)
    st.markdown(
        f"""
        <style>
        .stApp {{
            background-image: url("data:image/jpg;base64,{encoded}");
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
        }}
        </style>
        """,
        unsafe_allow_html=True
    )

add_bg("assets/5096160.jpg")
render_sidebar(show_logout=True)

# ---------------- LOAD MODELS (CACHED ⚡) ----------------
@st.cache_resource
def load_all_models():
    scaler = joblib.load("model/scaler.pkl")
    le = joblib.load("model/label_encoder.pkl")

    ann = load_model("model/ann_model.h5", compile=False)
    cnn = load_model("model/cnn_model.h5", compile=False)
    lstm = load_model("model/lstm_model.h5", compile=False)
    rnn = load_model("model/rnn_model.h5", compile=False)
    meta = load_model("model/meta_model.h5", compile=False)

    return scaler, le, ann, cnn, lstm, rnn, meta

scaler, le, ann, cnn, lstm, rnn, meta = load_all_models()

# ---------------- HEADER ----------------
st.markdown("""
<div class="hero-shell">
    <h1 class="hero-title">🛡 ACLR Manual Multi-Class Detection</h1>
    <p class="hero-text">
        Enter traffic values below to run detection workflow.
    </p>
</div>
""", unsafe_allow_html=True)

# ---------------- INPUT SECTION ----------------
col1, col2, col3, col4 = st.columns(4)

with col1:
    sbytes = st.number_input("Source Bytes", min_value=0.0, step=1.0)

with col2:
    dbytes = st.number_input("Destination Bytes", min_value=0.0, step=1.0)

with col3:
    rate = st.number_input("Rate", min_value=0.0, step=0.1)

with col4:
    ip_address = st.text_input("IP Address")

analyze = st.button("Predict", use_container_width=True)

# ---------------- VALIDATION + PREDICTION ----------------
if analyze:

    # ---- INPUT VALIDATION ----
    if ip_address.strip() == "":
        st.warning("⚠️ Please enter IP Address")
        st.stop()

    if sbytes <= 0 or dbytes <= 0 or rate <= 0:
        st.warning("⚠️ All numeric fields must be greater than 0")
        st.stop()

    try:
        ip_obj = ipaddress.ip_address(ip_address)
        st.success(f"Valid IP Address: {ip_obj}")
    except ValueError:
        st.error("❌ Invalid IP Address! (Example: 192.168.1.1)")
        st.stop()

    # ---- DATA PREPARATION ----
    input_data = scaler.transform([[sbytes, dbytes, rate]])
    input_seq = input_data.reshape(-1, 3, 1)

    # ---- MODEL PREDICTION (FAST ⚡) ----
    preds = np.hstack([
        ann.predict(input_data, verbose=0),
        cnn.predict(input_seq, verbose=0),
        lstm.predict(input_seq, verbose=0),
        rnn.predict(input_seq, verbose=0)
    ])

    final_pred = meta.predict(preds, verbose=0)

    attack_index = np.argmax(final_pred)
    attack = le.inverse_transform([attack_index])[0]
    confidence = float(np.max(final_pred) * 100)

    # ---- RISK LEVEL ----
    if confidence >= 80:
        risk = "🔴 HIGH"
    elif confidence >= 50:
        risk = "🟠 MEDIUM"
    else:
        risk = "🟢 LOW"

    # ---- RESULT DISPLAY ----
    c1, c2, c3 = st.columns(3)
    c1.metric("Attack Type", attack)
    c2.metric("Risk Level", risk)
    c3.metric("Confidence", f"{confidence:.2f}%")

    # ---- GAUGE CHART ----
    gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=confidence,
        title={'text': "Confidence"},
        gauge={'axis': {'range': [0, 100]}}
    ))
    st.plotly_chart(gauge, use_container_width=True)

    # ---- BAR CHART ----
    attack_classes = le.classes_
    values = np.zeros(len(attack_classes))
    values[attack_index] = confidence

    fig, ax = plt.subplots()
    ax.bar(attack_classes, values)
    plt.xticks(rotation=40, fontsize=8)
    st.pyplot(fig)

    # ---- SECURITY RECOMMENDATIONS ----
    st.markdown("## 🛡 Recommended Security Measures")

    measures = {
        "DoS": "Enable rate limiting, deploy firewall rules, use IDS/IPS.",
        "Exploits": "Update system patches, disable unused services.",
        "Fuzzers": "Input validation, implement strong API validation.",
        "Generic": "Deploy anomaly detection, monitor unusual traffic.",
        "Reconnaissance": "Disable ICMP response, block port scanning.",
        "Backdoor": "Scan system files, monitor unknown processes.",
        "Shellcode": "Enable endpoint protection, sandbox suspicious files.",
        "Worms": "Isolate infected devices, disable network sharing.",
        "Analysis": "Monitor logs, restrict sensitive data access.",
        "Normal": "No threat detected. Continue monitoring."
    }

    st.info(measures.get(attack, "No specific recommendation available"))
