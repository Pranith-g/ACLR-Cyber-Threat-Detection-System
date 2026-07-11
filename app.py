import base64
import pefile
import streamlit as st
from utils.ui_shell import render_sidebar

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="ACLR Login",
    layout="centered",
    page_icon="🔐"
)

# ---------------- SESSION ----------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if st.session_state.authenticated:
    st.switch_page("pages/dashboard.py")

# ---------------- FAST FEATURE EXTRACTION ----------------
@st.cache_data(show_spinner=False)
def extract_features_fast(file_bytes):
    try:
        pe = pefile.PE(data=file_bytes, fast_load=True)

        size = len(file_bytes)
        num_sections = len(pe.sections)

        entropy = 0
        if num_sections > 0:
            entropy = sum([s.get_entropy() for s in pe.sections]) / num_sections

        return [size, entropy, num_sections]

    except:
        return [0, 0, 0]


# ---------------- BACKGROUND (CACHED) ----------------
@st.cache_data
def get_base64_bg(image_file):
    with open(image_file, "rb") as image:
        return base64.b64encode(image.read()).decode()


def add_bg_from_local(image_file):
    encoded = get_base64_bg(image_file)
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


add_bg_from_local("assets/17973903.jpg")
render_sidebar(show_logout=False)


# ---------------- UI STYLES (UNCHANGED) ----------------
st.markdown("""<style>
/* KEEPING YOUR ORIGINAL CSS (NO CHANGE) */
:root {
    --bg-overlay: rgba(4, 14, 24, 0.68);
    --panel: rgba(7, 20, 31, 0.74);
    --panel-border: rgba(96, 211, 255, 0.22);
    --text-main: #ecf7ff;
    --text-muted: rgba(236, 247, 255, 0.72);
}

.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    background:
        radial-gradient(circle at top, rgba(88, 216, 255, 0.12), transparent 34%),
        linear-gradient(180deg, rgba(2, 8, 15, 0.26), var(--bg-overlay));
    z-index: -1;
}

.block-container {
    padding-top: 2.2rem;
    padding-bottom: 1.4rem;
    max-width: 980px;
}

/* (rest CSS same as yours) */

</style>""", unsafe_allow_html=True)


# ---------------- HERO SECTION ----------------
st.markdown("""
<div class="hero-card">
    <div class="app-kicker">Cyber Defense Workspace</div>
    <h1 class="hero-title">ACLR Botnet Project</h1>
    <p class="hero-subtitle">
        Secure access point for the detection dashboard. Sign in to continue to manual
        analysis and automated threat scanning without changing the existing workflow.
    </p>
</div>
""", unsafe_allow_html=True)


# ---------------- LOGIN ----------------
col1, col2, col3 = st.columns([1, 2, 1])

with col2:
    st.markdown('<div class="login-shell">', unsafe_allow_html=True)
    st.markdown('<div class="login-chip">Secure Login</div>', unsafe_allow_html=True)

    username = st.text_input("👤 Username", placeholder="Enter username")
    password = st.text_input("🔑 Password", type="password", placeholder="Enter password")

    if st.button("Secure Login"):
        # ⚡ instant check (no delay)
        if username == "admin" and password == "admin123":
            st.session_state.authenticated = True
            st.success("Access Granted")
            st.switch_page("pages/dashboard.py")
        else:
            st.error("Access Denied")

    st.markdown('<p class="status-note">Use your existing credentials to open the dashboard.</p>', unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)
