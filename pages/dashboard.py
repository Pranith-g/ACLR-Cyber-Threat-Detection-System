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
            linear-gradient(180deg, rgba(3, 10, 18, 0.18), rgba(3, 12, 21, 0.72));
        z-index: -1;
    }

    .block-container {
        padding-top: 1.7rem;
        padding-bottom: 1.4rem;
        max-width: 1120px;
    }

    .dashboard-hero {
        padding: 1.75rem 1.9rem;
        border-radius: 26px;
        background: linear-gradient(180deg, rgba(8, 23, 35, 0.88), rgba(4, 15, 25, 0.78));
        border: 1px solid rgba(96, 211, 255, 0.18);
        box-shadow: 0 18px 48px rgba(0, 0, 0, 0.28);
        color: #eef8ff;
        margin-bottom: 1.5rem;
    }

    .dashboard-kicker {
        display: inline-flex;
        align-items: center;
        padding: 0.38rem 0.9rem;
        border-radius: 999px;
        font-size: 0.8rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: #bfefff;
        background: rgba(88, 216, 255, 0.1);
        border: 1px solid rgba(96, 211, 255, 0.2);
    }

    .dashboard-title {
        margin: 0.95rem 0 0.5rem 0;
        font-size: 2.55rem;
        font-weight: 800;
        line-height: 1.12;
        color: #eef8ff;
    }

    .dashboard-copy {
        margin: 0;
        max-width: 760px;
        color: rgba(238, 248, 255, 0.74);
        font-size: 1.02rem;
        line-height: 1.65;
    }

    .dashboard-card {
        min-height: 210px;
        padding: 1.35rem;
        border-radius: 24px;
        background: rgba(8, 21, 31, 0.78);
        border: 1px solid rgba(96, 211, 255, 0.18);
        backdrop-filter: blur(12px);
        box-shadow: 0 16px 36px rgba(0, 0, 0, 0.22);
        margin-bottom: 0.9rem;
        color: #eef8ff;
    }

    .dashboard-card-icon {
        font-size: 2rem;
        margin-bottom: 0.85rem;
    }

    .dashboard-card h3 {
        margin: 0 0 0.8rem 0;
        font-size: 1.65rem;
        font-weight: 750;
        color: #eef8ff;
    }

    .dashboard-card p {
        margin: 0;
        color: rgba(238, 248, 255, 0.72);
        line-height: 1.62;
        font-size: 1rem;
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

    .stButton > button:hover {
        box-shadow: 0 16px 30px rgba(18, 148, 188, 0.28), 0 0 18px rgba(88, 216, 255, 0.14);
    }

    @media (max-width: 900px) {
        .dashboard-title {
            font-size: 2rem;
        }

        .dashboard-hero {
            padding: 1.35rem;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


st.markdown(
    """
    <div class="dashboard-hero">
        <div class="dashboard-kicker">Command Center</div>
        <div class="dashboard-title">ACLR Security Dashboard</div>
        <p class="dashboard-copy">
            Launch manual analysis or automated scanning from a clean control surface
            with a more focused workspace and simpler navigation.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)


col1, col2 = st.columns(2, gap="large")

with col1:
    st.markdown(
        """
        <div class="dashboard-card">
            <div class="dashboard-card-icon">🛡</div>
            <h3>Manual Detection</h3>
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
        <div class="dashboard-card">
            <div class="dashboard-card-icon">🌐</div>
            <h3>Threat Scanner</h3>
            <p>Open the automated detection workspace for file, URL, and IP-based scanning using the existing project logic.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if st.button("Open Threat Scanner"):
        st.switch_page("pages/2_Auto_Threat_Scan.py")
