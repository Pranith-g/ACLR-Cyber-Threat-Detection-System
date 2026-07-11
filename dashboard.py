import base64
import streamlit as st

from utils.ui_shell import render_sidebar


st.set_page_config(
    page_title="ACLR Dashboard",
    layout="wide",
    page_icon="🛡",
    initial_sidebar_state="collapsed",
)


if "authenticated" not in st.session_state or not st.session_state.authenticated:
    st.switch_page("app.py")


def add_bg(image_file):
    with open(image_file, "rb") as image:
        encoded = base64.b64encode(image.read()).decode()
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
        unsafe_allow_html=True,
    )


add_bg("assets/6057485.jpg")
render_sidebar(show_logout=True)


st.markdown(
    """
    <style>
    .stApp::before {
        content: "";
        position: fixed;
        inset: 0;
        background:
            radial-gradient(circle at top, rgba(88, 216, 255, 0.10), transparent 30%),
            linear-gradient(180deg, rgba(3, 10, 18, 0.20), rgba(3, 12, 21, 0.72));
        z-index: -1;
    }

    .block-container {
        padding-top: 1.7rem;
        max-width: 1120px;
    }

    .hero-shell {
        padding: 1.75rem 1.85rem;
        border-radius: 26px;
        background: linear-gradient(180deg, rgba(9, 24, 35, 0.86), rgba(5, 16, 24, 0.78));
        border: 1px solid rgba(96, 211, 255, 0.18);
        box-shadow: 0 18px 48px rgba(0, 0, 0, 0.28);
        margin-bottom: 1.5rem;
        color: #eef8ff;
    }

    .hero-title {
        margin: 0;
        font-size: 2.45rem;
        font-weight: 800;
        line-height: 1.15;
    }

    .hero-text {
        margin-top: 0.75rem;
        color: rgba(238, 248, 255, 0.72);
        line-height: 1.6;
        font-size: 1.02rem;
    }

    .stButton > button {
        width: 100%;
        min-height: 3.1rem;
        border-radius: 14px;
        border: 1px solid rgba(96, 211, 255, 0.22);
        background: linear-gradient(90deg, rgba(88, 216, 255, 0.96), rgba(123, 240, 207, 0.94));
        color: #06131d;
        font-size: 0.98rem !important;
        font-weight: 700;
        box-shadow: 0 12px 24px rgba(18, 148, 188, 0.22);
    }

    .card {
        min-height: 196px;
        padding: 1.35rem;
        border-radius: 24px;
        background: rgba(8, 21, 31, 0.78);
        border: 1px solid rgba(96, 211, 255, 0.18);
        backdrop-filter: blur(12px);
        box-shadow: 0 16px 36px rgba(0, 0, 0, 0.22);
        margin-bottom: 0.9rem;
        color: #eef8ff;
    }

    .card h3 {
        margin-top: 0.15rem;
        margin-bottom: 0.85rem;
        font-size: 1.65rem;
    }

    .card p {
        color: rgba(238, 248, 255, 0.72);
        line-height: 1.6;
        font-size: 1rem;
    }

    @media (max-width: 900px) {
        .hero-title {
            font-size: 2rem;
        }

        .hero-shell {
            padding: 1.35rem;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


st.markdown(
    """
    <div class="hero-shell">
        <div class="hero-title">ACLR Security Dashboard</div>
        <div class="hero-text">
            Launch manual analysis or automated scanning from a clean control surface
            with a more focused workspace and simpler navigation.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


col1, col2 = st.columns(2, gap="large")

with col1:
    st.markdown(
        """
        <div class="card">
            <h3>🛡 Manual Detection</h3>
            <p>Open the manual traffic analysis module and inspect predictions from the existing ensemble workflow.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if st.button("Open Manual Detection"):
        st.switch_page("pages/1_Manual_Detection.py")

with col2:
    st.markdown(
        """
        <div class="card">
            <h3>🌐 Threat Scanner</h3>
            <p>Open the automated detection workspace for file, URL, and IP-based scanning using the existing project logic.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if st.button("Open Threat Scanner"):
        st.switch_page("pages/2_Auto_Threat_Scan.py")
