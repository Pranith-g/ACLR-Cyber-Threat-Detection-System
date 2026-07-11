import streamlit as st


def inject_sidebar_css():
    st.markdown(
        """
        <style>
        section[data-testid="stSidebar"] {
            width: 228px !important;
            min-width: 228px !important;
            background: linear-gradient(180deg, rgba(8, 16, 28, 0.98), rgba(10, 19, 30, 0.95));
            border-right: 1px solid rgba(96, 211, 255, 0.08);
            box-shadow: 6px 0 18px rgba(0, 0, 0, 0.14);
        }

        section[data-testid="stSidebar"] [data-testid="stSidebarNav"] {
            display: none;
        }

        section[data-testid="stSidebar"] .block-container {
            padding-top: 0.85rem;
            padding-left: 0.7rem;
            padding-right: 0.7rem;
        }

        section[data-testid="stSidebar"][aria-expanded="false"] {
            min-width: 4.1rem !important;
            width: 4.1rem !important;
        }

        section[data-testid="stSidebar"][aria-expanded="false"] .block-container {
            padding-left: 0.2rem;
            padding-right: 0.2rem;
        }

        section[data-testid="stSidebar"][aria-expanded="false"] .custom-side-title,
        section[data-testid="stSidebar"][aria-expanded="false"] .sidebar-group-label,
        section[data-testid="stSidebar"][aria-expanded="false"] .stButton,
        section[data-testid="stSidebar"][aria-expanded="false"] [data-testid="stPageLink"] span[title] {
            display: none !important;
        }

        section[data-testid="stSidebar"][aria-expanded="false"] [data-testid="stPageLink"] a {
            justify-content: center !important;
            padding: 0.55rem 0 !important;
            margin-bottom: 0.35rem;
            min-height: 2.6rem;
        }

        .custom-side-title {
            margin: 0 0 0.8rem 0;
            padding: 0.62rem 0.82rem;
            border-radius: 12px;
            background: rgba(86, 210, 255, 0.05);
            border: 1px solid rgba(96, 211, 255, 0.08);
            color: #eef8ff;
            font-size: 1rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .sidebar-group-label {
            margin: 0.8rem 0 0.28rem 0.15rem;
            color: rgba(226, 242, 255, 0.68);
            font-size: 0.68rem;
            font-weight: 700;
            letter-spacing: 0.12em;
            text-transform: uppercase;
        }

        section[data-testid="stSidebar"] [data-testid="stPageLink"] a {
            border-radius: 11px;
            padding: 0.48rem 0.72rem;
            margin-bottom: 0.16rem;
            color: #eef8ff !important;
            font-size: 0.95rem !important;
            font-weight: 600 !important;
            background: transparent;
            text-decoration: none;
            transition: background 0.16s ease, transform 0.16s ease;
        }

        section[data-testid="stSidebar"] [data-testid="stPageLink"] a:hover {
            background: rgba(96, 211, 255, 0.08);
            transform: translateX(2px);
        }

        section[data-testid="stSidebar"] [data-testid="stPageLink"] a[aria-current="page"] {
            background: linear-gradient(90deg, rgba(95, 209, 255, 0.14), rgba(95, 209, 255, 0.06));
            border: 1px solid rgba(96, 211, 255, 0.12);
        }

        section[data-testid="stSidebar"] .stButton > button {
            width: 100%;
            border-radius: 11px;
            min-height: 2.4rem;
            font-size: 0.9rem;
            font-weight: 700;
            box-shadow: 0 8px 18px rgba(18, 148, 188, 0.14);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_sidebar(show_logout=False):
    inject_sidebar_css()
    with st.sidebar:
        st.markdown("<div class='custom-side-title'>ACLR</div>", unsafe_allow_html=True)
        st.markdown("<div class='sidebar-group-label'>Workspace</div>", unsafe_allow_html=True)
        st.page_link("app.py", label="Login", icon="🔐")
        st.page_link("pages/dashboard.py", label="Dashboard", icon="🧭")
        st.page_link("pages/1_Manual_Detection.py", label="Manual Detection", icon="🛡")
        st.page_link("pages/2_Auto_Threat_Scan.py", label="Auto Threat Scan", icon="🌐")
        if show_logout:
            st.markdown("<div class='sidebar-group-label'>Account</div>", unsafe_allow_html=True)
            st.button("Logout", on_click=lambda: st.session_state.update({"authenticated": False}))
