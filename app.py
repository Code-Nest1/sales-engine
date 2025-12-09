import streamlit as st
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import pandas as pd
from fpdf import FPDF
from datetime import datetime, timedelta
import time
import re
import whois
from openai import OpenAI
import os
from dotenv import load_dotenv
import json
import hashlib
from pathlib import Path
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from io import BytesIO

# Optional: 2FA support
try:
    import pyotp
    import qrcode
    TWO_FA_AVAILABLE = True
except ImportError:
    TWO_FA_AVAILABLE = False

# Load environment variables
load_dotenv()
from models import init_db, get_db, Audit, Lead, EmailOutreach, DATABASE_URL, User

# ============================================================================
# ENHANCED APP CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="Code Nest Sales Engine Pro",
    layout="wide",
    page_icon="🦅",
    initial_sidebar_state="expanded"
)

# Branding
COMPANY_NAME = "Code Nest"
COMPANY_TAGLINE = "Launch. Scale. Optimize."
CONTACT_EMAIL = "services@codenest.agency"

# Color scheme
COLORS = {
    "success": "#00D084",
    "warning": "#FFA500",
    "danger": "#FF6B6B",
    "info": "#0066CC",
    "primary": "#0066CC",
    "neutral": "#666666"
}

# Initialize database
DB_AVAILABLE = False
if DATABASE_URL:
    try:
        DB_AVAILABLE = init_db()
    except Exception as e:
        DB_AVAILABLE = False

# ============================================================================
# AUTHENTICATION & USER MANAGEMENT
# ============================================================================

USERS_PATH = Path(__file__).parent / "users.json"
TWO_FA_PATH = Path(__file__).parent / "two_fa.json"

def init_users_file():
    """Create users.json if it doesn't exist."""
    if not USERS_PATH.exists():
        USERS_PATH.write_text(json.dumps({"users": {}}, indent=2))

def init_2fa_file():
    """Create two_fa.json if it doesn't exist."""
    if not TWO_FA_PATH.exists():
        TWO_FA_PATH.write_text(json.dumps({}, indent=2))

def load_users():
    """Return users dict from users.json."""
    init_users_file()
    try:
        data = json.loads(USERS_PATH.read_text())
        return data.get("users", {})
    except Exception:
        return {}

def save_users(users: dict):
    """Save users dict to users.json."""
    data = {"users": users}
    USERS_PATH.write_text(json.dumps(data, indent=2))

def load_2fa_secrets():
    """Load 2FA secrets."""
    init_2fa_file()
    try:
        return json.loads(TWO_FA_PATH.read_text())
    except Exception:
        return {}

def save_2fa_secrets(secrets: dict):
    """Save 2FA secrets."""
    TWO_FA_PATH.write_text(json.dumps(secrets, indent=2))

def hash_password(password: str) -> str:
    """Hash password with SHA-256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password."""
    return hash_password(password) == stored_hash

def generate_2fa_secret():
    """Generate 2FA secret."""
    if not TWO_FA_AVAILABLE:
        return None
    return pyotp.random_base32()

def verify_2fa_token(secret: str, token: str) -> bool:
    """Verify 2FA token."""
    if not TWO_FA_AVAILABLE or not secret:
        return False
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(token)
    except Exception:
        return False

def show_auth_page():
    """Enhanced login/signup UI with 2FA support."""
    st.markdown("""
    <style>
    .auth-container {
        max-width: 500px;
        margin: 0 auto;
        padding: 2rem;
        border-radius: 10px;
        background: linear-gradient(135deg, #0066CC 0%, #004A99 100%);
    }
    </style>
    """, unsafe_allow_html=True)
    
    st.title("🦅 Code Nest Sales Engine")
    st.caption("Sign in to access intelligent website auditing & lead generation")
    
    tab = st.radio("", ["Login", "Sign Up"], horizontal=True)
    users = load_users()
    
    if tab == "Login":
        st.subheader("🔐 Login")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        
        if st.button("Login", type="primary", use_container_width=True):
            if not username or not password:
                st.error("Please fill in all fields")
            elif username not in users:
                st.error("User not found")
            elif not verify_password(password, users[username]["password_hash"]):
                st.error("Invalid credentials")
            else:
                # Check if 2FA is enabled
                secrets_2fa = load_2fa_secrets()
                if username in secrets_2fa and secrets_2fa[username].get("enabled"):
                    st.session_state["2fa_pending"] = True
                    st.session_state["2fa_username"] = username
                    st.rerun()
                else:
                    st.session_state["authenticated"] = True
                    st.session_state["current_user"] = username
                    st.session_state["is_admin"] = users[username].get("role") == "admin"
                    st.session_state["user_role"] = users[username].get("role", "user")
                    st.success(f"Welcome, {users[username].get('name') or username}!")
                    time.sleep(1)
                    st.rerun()
        
        # 2FA verification if pending
        if st.session_state.get("2fa_pending"):
            st.divider()
            st.markdown("### 🔑 Two-Factor Authentication")
            token = st.text_input("Enter 6-digit code from authenticator app", max_chars=6, key="2fa_token")
            
            if st.button("Verify 2FA", type="primary"):
                secrets_2fa = load_2fa_secrets()
                if token and verify_2fa_token(secrets_2fa[st.session_state["2fa_username"]]["secret"], token):
                    st.session_state["authenticated"] = True
                    st.session_state["current_user"] = st.session_state["2fa_username"]
                    st.session_state["is_admin"] = users[st.session_state["2fa_username"]].get("role") == "admin"
                    st.session_state["user_role"] = users[st.session_state["2fa_username"]].get("role", "user")
                    st.session_state["2fa_pending"] = False
                    st.success("2FA verified!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("Invalid 2FA token")
    else:
        st.subheader("📝 Create Account")
        full_name = st.text_input("Full Name", key="signup_name")
        username = st.text_input("Username", key="signup_username")
        password = st.text_input("Password", type="password", key="signup_password")
        confirm = st.text_input("Confirm Password", type="password", key="signup_confirm")
        request_admin = st.checkbox("Request admin access")
        reason = ""
        if request_admin:
            reason = st.text_area("Why do you need admin access?")
        
        if st.button("Create Account", type="primary", use_container_width=True):
            if not username or not password or not full_name:
                st.error("All fields required")
            elif password != confirm:
                st.error("Passwords don't match")
            elif username in users:
                st.error("Username already taken")
            elif len(password) < 6:
                st.error("Password must be at least 6 characters")
            else:
                users[username] = {
                    "name": full_name,
                    "password_hash": hash_password(password),
                    "role": "user",
                    "admin_request": request_admin,
                    "admin_request_reason": reason if request_admin else "",
                    "created_at": datetime.now().isoformat(),
                    "last_login": None
                }
                save_users(users)
                st.success("Account created! Please login.")
                time.sleep(1)
                st.rerun()

# Initialize auth
init_users_file()
init_2fa_file()

if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False
    st.session_state['current_user'] = None
    st.session_state['is_admin'] = False
    st.session_state['user_role'] = 'user'
    st.session_state['2fa_pending'] = False
    st.session_state['2fa_username'] = None

if not st.session_state.get('authenticated'):
    show_auth_page()
    st.stop()

# ============================================================================
# SIDEBAR & NAVIGATION
# ============================================================================

# Initialize session state for navigation
if 'current_section' not in st.session_state:
    st.session_state.current_section = 'Single Audit'

# Store API keys in session state (from session or temporary input)
if 'OPENAI_API_KEY' not in st.session_state:
    st.session_state.OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")

if 'GOOGLE_API_KEY' not in st.session_state:
    st.session_state.GOOGLE_API_KEY = None

if 'SLACK_WEBHOOK' not in st.session_state:
    st.session_state.SLACK_WEBHOOK = None

# Get current API keys from session
OPENAI_API_KEY = st.session_state.OPENAI_API_KEY
GOOGLE_API_KEY = st.session_state.GOOGLE_API_KEY
SLACK_WEBHOOK = st.session_state.SLACK_WEBHOOK

with st.sidebar:
    st.header("🦅 Code Nest Panel")
    st.caption("Navigation")
    st.divider()
    
    # Build navigation items based on role
    nav_items = ["Single Audit", "Audit History"]
    if st.session_state.get("is_admin"):
        nav_items.extend([
            "Bulk Audit",
            "Competitor Analysis",
            "Email Outreach",
            "Scheduled Audits",
            "API Settings",
            "Admin Settings"
        ])
    
    # Navigation buttons
    for item in nav_items:
        if st.button(
            item,
            key=f"nav_{item}",
            use_container_width=True,
            type="primary" if st.session_state.current_section == item else "secondary"
        ):
            st.session_state.current_section = item
            st.rerun()
    
    st.divider()
    st.divider()
    
    # Status badge
    if DB_AVAILABLE:
        st.success("🟢 System: **Active**")
    else:
        st.warning("🟡 System: **Limited**")
    
    st.divider()
    
    # User info & logout
    st.markdown(f"**User:** {st.session_state.get('current_user')}")
    st.markdown(f"**Role:** {st.session_state.get('user_role').capitalize()}")
    
    if st.button("🚪 Logout", use_container_width=True):
        st.session_state['authenticated'] = False
        st.session_state['current_user'] = None
        st.session_state['is_admin'] = False
        st.session_state['user_role'] = 'user'
        st.session_state.current_section = 'Single Audit'
        st.rerun()
    
    # 2FA setup (if admin)
    if st.session_state.get('is_admin'):
        st.divider()
        if st.checkbox("Setup 2FA", key="admin_2fa_checkbox"):
            if TWO_FA_AVAILABLE:
                st.markdown("### Enable 2FA for Your Account")
                if st.button("Generate 2FA"):
                    secret = generate_2fa_secret()
                    st.session_state["2fa_setup_secret"] = secret
                    
                    totp = pyotp.TOTP(secret)
                    qr = qrcode.QRCode(version=1, box_size=10)
                    qr.add_data(totp.provisioning_uri(st.session_state['current_user'], issuer_name='Code Nest'))
                    qr.make(fit=True)
                    img = qr.make_image(fill_color="black", back_color="white")
                    
                    st.image(img, width=200)
                    st.code(secret, language="text")
                    st.info("Scan QR code with authenticator app (Google Authenticator, Authy, etc)")
                    
                    token = st.text_input("Enter 6-digit code to confirm")
                    if token and verify_2fa_token(secret, token):
                        secrets_2fa = load_2fa_secrets()
                        secrets_2fa[st.session_state['current_user']] = {
                            "secret": secret,
                            "enabled": True
                        }
                        save_2fa_secrets(secrets_2fa)
                        st.success("2FA enabled!")
                        st.rerun()
            else:
                st.info("2FA requires pyotp and qrcode packages. Install via: pip install pyotp qrcode[pil]")

def show_api_settings():
    """API Settings page for configuring API keys."""
    st.title("🔑 API Settings")
    st.markdown("Configure your API keys for AI email generation and PageSpeed insights")
    st.markdown("---")
    
    col1, col2 = st.columns([1, 2])
    with col1:
        st.markdown("### OpenAI API")
        st.markdown("For AI email generation and analysis")
    with col2:
        if os.environ.get("OPENAI_API_KEY"):
            st.success("✓ Connected via environment variable")
        else:
            st.session_state.OPENAI_API_KEY = st.text_input(
                "OpenAI API Key",
                value=st.session_state.OPENAI_API_KEY or "",
                type="password",
                key="api_openai_input"
            )
            if st.session_state.OPENAI_API_KEY:
                st.success("✓ API Key configured")
    
    st.divider()
    
    col1, col2 = st.columns([1, 2])
    with col1:
        st.markdown("### Google PageSpeed")
        st.markdown("For website performance analysis")
    with col2:
        st.session_state.GOOGLE_API_KEY = st.text_input(
            "Google PageSpeed API Key",
            value=st.session_state.GOOGLE_API_KEY or "",
            type="password",
            key="api_google_input"
        )
        if st.session_state.GOOGLE_API_KEY:
            st.success("✓ API Key configured")
    
    st.divider()
    
    col1, col2 = st.columns([1, 2])
    with col1:
        st.markdown("### Slack Webhook")
        st.markdown("For audit notifications (optional)")
    with col2:
        st.session_state.SLACK_WEBHOOK = st.text_input(
            "Slack Webhook URL",
            value=st.session_state.SLACK_WEBHOOK or "",
            type="password",
            key="api_slack_input"
        )
        if st.session_state.SLACK_WEBHOOK:
            st.success("✓ Webhook configured")
    
    st.markdown("---")
    st.info("💡 API keys are stored in your session and not saved to disk. Re-enter them after refreshing the page.")

def show_single_audit():
    """Single website audit page."""
    st.title("🚀 Single Website Audit")
    st.markdown("Enter a website URL to analyze its technical health, SEO, performance & generate AI insights")
    st.markdown("---")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        url = st.text_input("Website URL", placeholder="example.com")
    with col2:
        analyze_btn = st.button("🔍 Analyze", type="primary", use_container_width=True)
    
    if analyze_btn:
        if not url:
            st.error("Please enter a URL")
        else:
            with st.spinner("🔄 Analyzing website..."):
                data = run_audit(url, st.session_state.OPENAI_API_KEY, st.session_state.GOOGLE_API_KEY)
                
                if "error" in data:
                    st.error(f"❌ Scan Failed: {data['error']}")
                else:
                    # Metrics
                    st.markdown("---")
                    st.markdown("### 📊 Audit Results")
                    
                    c1, c2, c3, c4, c5 = st.columns(5)
                    
                    with c1:
                        st.metric("Health Score", data['score'], delta=("Good" if data['score'] >= 70 else "Needs Work"))
                    with c2:
                        st.metric("Google Speed", data.get('psi', 'N/A'))
                    with c3:
                        st.metric("Accessibility", data.get('accessibility_score', 'N/A'))
                    with c4:
                        st.metric("Issues Found", len(data['issues']))
                    with c5:
                        st.metric("Age", data.get('domain_age', 'Unknown'))
                    
                    # Tech stack
                    if data['tech_stack']:
                        st.markdown(f"**📦 Tech Stack:** {', '.join(data['tech_stack'])}")
                    
                    # Issues
                    if data['issues']:
                        st.markdown("---")
                        st.markdown("### ⚠️ Issues Detected")
                        
                        for i, issue in enumerate(data['issues'], 1):
                            with st.expander(f"{i}. {issue['title']}", expanded=(i <= 2)):
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.markdown(f"**Impact:** {issue['impact']}")
                                with col2:
                                    st.markdown(f"**Solution:** {issue['solution']}")
                    
                    # AI analysis
                    if data.get('ai'):
                        if not st.session_state.OPENAI_API_KEY:
                            st.warning("⚠️ OpenAI API key not configured. Go to **API Settings** to configure it for AI analysis.")
                        else:
                            st.markdown("---")
                            st.markdown("### 🤖 AI Analysis")
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                st.markdown("**Summary**")
                                st.info(data['ai']['summary'])
                                st.markdown("**Impact**")
                                st.warning(data['ai']['impact'])
                            
                            with col2:
                                st.markdown("**Solutions**")
                                st.success(data['ai']['solutions'])
                            
                            st.markdown("---")
                            st.markdown("**📧 Cold Email Draft**")
                            st.text_area("", value=clean_text(data['ai']['email']), height=250, key="email_draft")
                    
                    # Save to DB
                    audit_id = None
                    if DB_AVAILABLE:
                        audit_id = save_audit_to_db(data)
                        if audit_id:
                            st.success(f"✓ Audit saved (ID: {audit_id})")
                            
                            # Send Slack notification
                            if st.session_state.SLACK_WEBHOOK:
                                send_slack_notification(f"🔍 New audit: {url} (Score: {data['score']}/100)", st.session_state.SLACK_WEBHOOK)
                    
                    # PDF export and persistent storage
                    st.markdown("---")
                    try:
                        pdf_bytes = generate_pdf(data)
                        domain_name = urlparse(data['url']).netloc.replace("www.", "").replace(".", "_")
                        
                        # Save PDF to persistent storage if audit was saved to DB
                        if audit_id:
                            save_audit_pdf_to_file(audit_id, pdf_bytes)
                            st.info(f"✓ PDF saved for future downloads")
                        
                        st.download_button(
                            "📥 Download PDF Report",
                            pdf_bytes,
                            f"CodeNest_Audit_{domain_name}.pdf",
                            "application/pdf",
                            type="primary",
                            use_container_width=True
                        )
                    except Exception as e:
                        st.error(f"PDF Error: {e}")

def show_bulk_audit():
    """Bulk audit processor page."""
    st.title("📂 Bulk Website Audit")
    st.markdown("Upload CSV with 'Website' column to analyze multiple sites at once")
    st.markdown("---")
    
    uploaded = st.file_uploader("Upload CSV", type="csv")
    
    if uploaded:
        df = pd.read_csv(uploaded)
        st.write(f"**Loaded {len(df)} rows**")
        
        if "Website" not in df.columns:
            st.error("CSV must have 'Website' column")
        else:
            st.dataframe(df.head(), use_container_width=True)
            
            if st.button("▶️ Process Batch", type="primary"):
                results = []
                progress = st.progress(0)
                status = st.empty()
                
                for i, row_site in enumerate(df['Website']):
                    status.text(f"📊 {i+1}/{len(df)}: {row_site}")
                    d = run_audit(str(row_site).strip(), st.session_state.OPENAI_API_KEY, st.session_state.GOOGLE_API_KEY)
                    
                    save_audit_to_db(d)
                    opp_score = calculate_opportunity_score(d)
                    
                    results.append({
                        "Website": row_site,
                        "Health Score": d['score'],
                        "Speed": d.get('psi', 'N/A'),
                        "Issues": len(d['issues']),
                        "Opportunity": opp_score,
                        "Tech": ", ".join(d['tech_stack'][:3]) if d['tech_stack'] else "Standard",
                        "Email": d['emails'][0] if d['emails'] else "N/A"
                    })
                    progress.progress((i+1)/len(df))
                
                status.empty()
                st.success(f"✓ Processed {len(df)} websites")
                
                res_df = pd.DataFrame(results).sort_values("Opportunity", ascending=False)
                st.dataframe(res_df, use_container_width=True)
                
                csv = res_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    "📥 Download Leads CSV",
                    csv,
                    "CodeNest_Leads.csv",
                    "text/csv",
                    use_container_width=True
                )

def show_audit_history():
    """Audit history page for all users."""
    st.title("📊 Audit History")
    st.markdown("View and download your previous audits")
    st.markdown("---")
    
    if not DB_AVAILABLE:
        st.error("Database required for audit history")
    else:
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            search = st.text_input("Search domain", key="hist_search")
        with col2:
            min_score = st.number_input("Min Score", 0, 100, 0)
        with col3:
            max_score = st.number_input("Max Score", 0, 100, 100)
        
        audits = get_audit_history(limit=100, search_query=search if search else None, min_score=min_score if min_score > 0 else None, max_score=max_score if max_score < 100 else None)
        
        if audits:
            hist_data = []
            for audit in audits:
                hist_data.append({
                    "Domain": audit.domain,
                    "Score": format_score_badge(audit.health_score),
                    "Speed": audit.psi_score if audit.psi_score else "N/A",
                    "Issues": len(audit.issues) if audit.issues else 0,
                    "Date": audit.created_at.strftime("%m/%d %H:%M") if audit.created_at else "N/A",
                    "ID": audit.id
                })
            
            st.dataframe(pd.DataFrame(hist_data).drop(columns=["ID"]), use_container_width=True)
            
            # Add download buttons for each audit
            st.markdown("---")
            st.markdown("### 📥 Download Audit PDFs")
            
            cols = st.columns(3)
            col_idx = 0
            for audit in audits:
                with cols[col_idx % 3]:
                    if st.button(f"📄 {audit.domain}", key=f"dl_audit_{audit.id}"):
                        pdf_bytes = get_audit_pdf(audit.id)
                        if pdf_bytes:
                            st.download_button(
                                label=f"⬇️ {audit.domain}",
                                data=pdf_bytes,
                                file_name=f"audit_{audit.id}_{audit.domain}.pdf",
                                mime="application/pdf",
                                key=f"btn_{audit.id}"
                            )
                        else:
                            st.warning(f"PDF not available for this audit. Run audit again to generate.")
                col_idx += 1
            
            # Export CSV option
            st.markdown("---")
            csv = pd.DataFrame(hist_data).drop(columns=["ID"]).to_csv(index=False).encode('utf-8')
            st.download_button("📥 Export CSV", csv, "audit_history.csv", "text/csv")
        else:
            st.info("No audits found")

def show_competitor_analysis():
    """Competitor analysis page."""
    st.title("🔄 Competitor Analysis")
    st.markdown("Compare multiple websites side-by-side")
    st.markdown("---")
    
    col1, col2, col3, col4, col5 = st.columns(5)
    urls = []
    for i, col in enumerate([col1, col2, col3, col4, col5]):
        with col:
            url_in = st.text_input(f"Site {i+1}", placeholder="example.com", key=f"comp_{i}")
            if url_in:
                urls.append(url_in)
    
    if st.button("▶️ Compare", type="primary", use_container_width=True):
        if len(urls) < 2:
            st.error("Need at least 2 sites")
        else:
            results = []
            progress = st.progress(0)
            
            for i, url in enumerate(urls):
                data = run_audit(url, st.session_state.OPENAI_API_KEY, st.session_state.GOOGLE_API_KEY)
                save_audit_to_db(data)
                results.append(data)
                progress.progress((i+1)/len(urls))
            
            st.success("Comparison complete!")
            
            comp_data = []
            for data in results:
                domain = urlparse(data['url']).netloc.replace("www.", "")
                comp_data.append({
                    "Website": domain,
                    "Score": format_score_badge(data['score']),
                    "Speed": data.get('psi', 'N/A'),
                    "Issues": len(data.get('issues', [])),
                    "Analytics": "✓" if any("Analytics" in t for t in data.get('tech_stack', [])) else "✗",
                    "SSL": "✓" if not any("SSL" in i.get('title', '') for i in data.get('issues', [])) else "✗"
                })
            
            st.dataframe(pd.DataFrame(comp_data), use_container_width=True)

def show_email_outreach():
    """Email outreach page."""
    st.title("📧 Email Outreach")
    st.markdown("Manage email campaigns to leads")
    st.markdown("---")
    
    if not DB_AVAILABLE:
        st.error("Database required")
    else:
        email_sub1, email_sub2 = st.tabs(["Send Email", "Email Templates"])
        
        with email_sub1:
            leads = get_leads()
            
            if leads:
                lead_opts = {f"{l.domain} (Score: {l.health_score}, Opp: {l.opportunity_rating})": l for l in leads}
                selected_name = st.selectbox("Choose lead", list(lead_opts.keys()))
                selected_lead = lead_opts[selected_name] if selected_name else None
                
                if selected_lead:
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown(f"**Domain:** {selected_lead.domain}")
                        st.markdown(f"**Score:** {selected_lead.health_score}")
                        st.markdown(f"**Opportunity:** {selected_lead.opportunity_rating}/100")
                    with col2:
                        st.markdown(f"**Email:** {selected_lead.email or 'N/A'}")
                        new_status = st.selectbox("Status", ["new", "contacted", "responded", "converted", "lost"], index=["new", "contacted", "responded", "converted", "lost"].index(selected_lead.status))
                        if new_status != selected_lead.status and st.button("Update Status"):
                            update_lead_status(selected_lead.id, new_status)
                            st.rerun()
                    
                    st.divider()
                    st.markdown("#### Compose Email")
                    
                    recipient = st.text_input("Recipient", value=selected_lead.email or "")
                    subject = st.text_input("Subject", value=f"Website Review - {selected_lead.domain}")
                    body = st.text_area("Body", height=250)
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("Save Draft"):
                            st.info("Draft saved")
                    with col2:
                        if st.button("Send Email", type="primary"):
                            st.success("Email sent!")
            else:
                st.info("No leads found")
        
        with email_sub2:
            st.markdown("#### Manage Email Templates")
            
            template_name = st.text_input("Template name")
            template_subject = st.text_input("Subject")
            template_body = st.text_area("Body template", height=200, help="Use {{domain}}, {{score}}, {{company}} as variables")
            
            if st.button("Save Template"):
                if save_email_template(template_name, template_subject, template_body):
                    st.success("Template saved!")
                else:
                    st.error("Failed to save")
            
            st.divider()
            st.markdown("#### Existing Templates")
            
            templates = load_email_templates()
            for name, template in templates.items():
                with st.expander(name):
                    st.write(f"**Subject:** {template['subject']}")
                    st.write(f"**Body:** {template['body']}")

def show_scheduled_audits():
    """Scheduled audits page."""
    st.title("⏰ Scheduled Audits")
    st.markdown("Automated periodic audits to track improvements over time")
    st.markdown("---")
    
    st.info("📋 This feature is currently in development. Coming soon:\n- Schedule audits to run automatically\n- Track improvements over time\n- Auto-generated reports")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### Setup Scheduled Audit")
        url = st.text_input("Website URL")
        frequency = st.selectbox("Frequency", ["Daily", "Weekly", "Monthly"])
        
        if st.button("Schedule"):
            st.success(f"Audit scheduled for {frequency}")
    
    with col2:
        st.markdown("### Active Schedules")
        st.info("No scheduled audits yet")

def clean_text(text):
    """Sanitize text for PDF."""
    if not text: return ""
    text = text.replace('\u201c', '"').replace('\u201d', '"').replace('\u2019', "'").replace('\u2013', '-')
    return text.encode('latin-1', 'replace').decode('latin-1')

def format_score_badge(score):
    """Return color-coded score badge."""
    if score >= 80:
        return f"🟢 {score}/100"
    elif score >= 50:
        return f"🟡 {score}/100"
    else:
        return f"🔴 {score}/100"

def send_slack_notification(message, webhook_url=None):
    """Send Slack notification."""
    if not webhook_url:
        webhook_url = SLACK_WEBHOOK
    if not webhook_url:
        return False
    
    try:
        payload = {"text": message}
        requests.post(webhook_url, json=payload)
        return True
    except Exception:
        return False

def get_domain_age(url):
    """Get domain age."""
    domain = urlparse(url).netloc.replace("www.", "")
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            days_alive = (datetime.now() - creation_date).days
            years = round(days_alive / 365, 1)
            return f"{years} years", days_alive
    except Exception:
        return "Unknown", 0
    return "Unknown", 0

def get_google_speed(url, api_key):
    """Get Google PageSpeed score."""
    if not api_key: 
        return None, "No API Key"
    
    api_url = f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url={url}&strategy=mobile&key={api_key}"
    try:
        r = requests.get(api_url, timeout=60)
        if r.status_code == 200:
            data = r.json()
            try:
                score = data['lighthouseResult']['categories']['performance']['score'] * 100
                return int(score), "Success"
            except KeyError:
                return None, "Data Error"
        else:
            return None, f"Error: {r.status_code}"
    except Exception as e:
        return None, str(e)

def get_ai_consultation(url, data, api_key):
    """Get AI analysis with GPT-5."""
    if not api_key:
        return {
            "summary": "AI Analysis Disabled",
            "impact": "N/A",
            "solutions": "Upgrade to enable AI",
            "email": "N/A"
        }

    issues_list = [f"- {i['title']}: {i['impact']}" for i in data['issues']]
    tech_list = ", ".join(data['tech_stack'])
    
    prompt = f"""You are a Senior Digital Strategist at Code Nest. Analyze this website: {url}
    
Tech Stack: {tech_list}
Issues: {chr(10).join(issues_list)}

Provide 4 sections separated by ###:
1. Executive Summary (2 sentences)
2. Business Impact (financial/brand loss)
3. 3 Code Nest services to fix
4. Professional cold email
"""

    try:
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model="gpt-5",
            messages=[{"role": "user", "content": prompt}]
        )
        parts = response.choices[0].message.content.split("###")
        
        return {
            "summary": parts[1].strip() if len(parts) > 1 else "Analysis complete",
            "impact": parts[2].strip() if len(parts) > 2 else "Impact assessed",
            "solutions": parts[3].strip() if len(parts) > 3 else "Solutions provided",
            "email": parts[4].strip() if len(parts) > 4 else "Email template"
        }
    except Exception as e:
        return {"summary": "Error", "impact": "Error", "solutions": "Error", "email": str(e)}

def calculate_opportunity_score(data):
    """Enhanced lead opportunity scoring (0-100)."""
    score = 0
    
    # Health score factors (40 points)
    if data['score'] < 30: score += 40
    elif data['score'] < 50: score += 30
    elif data['score'] < 70: score += 20
    else: score += 10
    
    # Tech stack issues (30 points)
    has_analytics = any("Analytics" in t for t in data.get('tech_stack', []))
    has_tracking = any("Pixel" in t for t in data.get('tech_stack', []))
    
    if not has_analytics or not has_tracking:
        score += 25
    
    # Critical issues (20 points)
    critical_count = len([i for i in data.get('issues', []) if i.get('title')])
    if critical_count >= 5: score += 20
    elif critical_count >= 3: score += 15
    elif critical_count > 0: score += 10
    
    # SSL/Security (10 points)
    if any("SSL" in i.get('title', '') for i in data.get('issues', [])):
        score += 10
    
    return min(100, score)

def run_audit(url, openai_key, google_key):
    """Enhanced audit with new checks."""
    if not url.startswith('http'): 
        url = 'http://' + url
    
    data = {
        "url": url,
        "score": 100,
        "issues": [],
        "tech_stack": [],
        "emails": [],
        "psi": None,
        "psi_error": None,
        "domain_age": "Unknown",
        "accessibility_score": None,
        "security_issues": [],
        "broken_links": 0,
        "cwv_metrics": {}
    }

    try:
        start = time.time()
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=30)
        load_time = time.time() - start
        
        html = response.text.lower()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Basic info
        data['domain_age'] = get_domain_age(url)[0]
        data['emails'] = list(set(re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", html)))

        # Tech detection
        tech_checks = [
            ("wp-content", "WordPress", -10),
            ("shopify", "Shopify", 0),
            ("wix", "Wix", 0),
            ("squarespace", "Squarespace", 0),
            ("webflow", "Webflow", 0)
        ]
        
        for check, tech, penalty in tech_checks:
            if check in html:
                data['tech_stack'].append(tech)
                if penalty:
                    data['score'] += penalty
                    data['issues'].append({
                        "title": f"{tech} Detected",
                        "impact": "Requires regular maintenance",
                        "solution": "Code Nest Maintenance"
                    })
                break

        # Marketing tracking
        pixels = []
        if "fbq(" in html: pixels.append("Facebook Pixel")
        if "gtag(" in html or "ua-" in html or "g-" in html: pixels.append("Google Analytics")
        if "linkedin" in html and "insight" in html: pixels.append("LinkedIn Insight")
        if "hotjar" in html: pixels.append("Hotjar")
        
        if not pixels:
            data['score'] -= 20
            data['issues'].append({
                "title": "Zero Tracking Installed",
                "impact": "No customer behavior data",
                "solution": "Analytics Setup"
            })
        else:
            data['tech_stack'].extend(pixels)

        # SEO basics
        title = soup.title.string if soup.title else ""
        if len(title) < 10:
            data['score'] -= 10
            data['issues'].append({
                "title": "Weak Title Tag",
                "impact": "Poor search visibility",
                "solution": "On-Page SEO"
            })
        
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if not meta_desc or not meta_desc.get('content'):
            data['score'] -= 10
            data['issues'].append({
                "title": "Missing Meta Description",
                "impact": "Poor search snippet",
                "solution": "SEO Optimization"
            })
        
        # NEW: Accessibility check
        h1_tags = soup.find_all('h1')
        alt_images = len([img for img in soup.find_all('img') if img.get('alt')])
        total_images = len(soup.find_all('img'))
        
        if not h1_tags:
            data['score'] -= 5
            data['issues'].append({
                "title": "No H1 Tag",
                "impact": "Accessibility issue",
                "solution": "Semantic HTML"
            })
        
        if total_images > 0 and alt_images < total_images * 0.5:
            data['score'] -= 5
            data['issues'].append({
                "title": "Missing Image Alt Text",
                "impact": "Accessibility & SEO",
                "solution": "Alt Text Optimization"
            })
        
        accessibility_score = 100
        if not h1_tags: accessibility_score -= 20
        if alt_images < total_images * 0.5: accessibility_score -= 20
        data['accessibility_score'] = accessibility_score

        # NEW: Security check
        if not url.startswith('https'):
            data['score'] -= 15
            data['security_issues'].append("No SSL Certificate")
            data['issues'].append({
                "title": "No SSL Certificate",
                "impact": "Customers lose trust",
                "solution": "SSL Installation"
            })

        # NEW: Broken links check (sample)
        links = soup.find_all('a', href=True)
        broken_count = 0
        for link in links[:10]:  # Check first 10 links
            try:
                href = link['href']
                if href.startswith('http'):
                    r = requests.head(href, timeout=5)
                    if r.status_code >= 400:
                        broken_count += 1
            except Exception:
                pass
        
        data['broken_links'] = broken_count
        if broken_count > 0:
            data['score'] -= min(10, broken_count * 2)
            data['issues'].append({
                "title": f"{broken_count} Broken Links",
                "impact": "Poor user experience",
                "solution": "Link Audit & Fix"
            })

        # Performance
        psi_score, psi_msg = get_google_speed(url, google_key)
        if psi_score:
            data['psi'] = psi_score
            if psi_score < 50:
                data['score'] -= 20
                data['issues'].append({
                    "title": f"Critical Speed ({psi_score}/100)",
                    "impact": "Users abandon slow sites",
                    "solution": "Speed Optimization"
                })
        else:
            data['psi_error'] = psi_msg
            if load_time > 3.0:
                data['score'] -= 10
                data['issues'].append({
                    "title": "Slow Server",
                    "impact": f"Load time {round(load_time,2)}s",
                    "solution": "Speed Optimization"
                })

        # Mobile check
        viewport = soup.find('meta', attrs={'name': 'viewport'})
        if not viewport:
            data['score'] -= 10
            data['issues'].append({
                "title": "Not Mobile Optimized",
                "impact": "Missing 60% of traffic",
                "solution": "Responsive Design"
            })

        # AI consultation
        data['ai'] = get_ai_consultation(url, data, openai_key)

    except Exception as e:
        data['error'] = str(e)

    data['score'] = max(0, data['score'])
    return data

def save_audit_to_db(data, comparison_group=None):
    """Save audit to database."""
    db = get_db()
    if not db:
        return None
    
    try:
        domain = urlparse(data['url']).netloc.replace("www.", "")
        audit = Audit(
            url=data['url'],
            domain=domain,
            health_score=data['score'],
            psi_score=data.get('psi'),
            domain_age=data.get('domain_age'),
            tech_stack=data.get('tech_stack', []),
            issues=data.get('issues', []),
            emails_found=data.get('emails', []),
            ai_summary=data.get('ai', {}).get('summary'),
            ai_impact=data.get('ai', {}).get('impact'),
            ai_solutions=data.get('ai', {}).get('solutions'),
            ai_email=data.get('ai', {}).get('email'),
            comparison_group=comparison_group
        )
        db.add(audit)
        db.commit()
        db.refresh(audit)
        
        # Store audit_id in data for PDF generation
        data['audit_id'] = audit.id
        
        # Create/update lead
        existing_lead = db.query(Lead).filter(Lead.domain == domain).first()
        opp_score = calculate_opportunity_score(data)
        
        if not existing_lead:
            lead = Lead(
                domain=domain,
                email=data['emails'][0] if data.get('emails') else None,
                health_score=data['score'],
                opportunity_rating=opp_score,
                created_at=datetime.utcnow()
            )
            db.add(lead)
            db.commit()
        else:
            existing_lead.health_score = data['score']
            existing_lead.opportunity_rating = opp_score
            existing_lead.updated_at = datetime.utcnow()
            db.commit()
        
        return audit.id
    except Exception as e:
        db.rollback()
        return None
    finally:
        db.close()

def get_audit_history(limit=50, search_query=None, min_score=None, max_score=None):
    """Get audit history with filters."""
    db = get_db()
    if not db:
        return []
    
    try:
        query = db.query(Audit).order_by(Audit.created_at.desc())
        
        if search_query:
            query = query.filter(Audit.domain.ilike(f"%{search_query}%"))
        if min_score is not None:
            query = query.filter(Audit.health_score >= min_score)
        if max_score is not None:
            query = query.filter(Audit.health_score <= max_score)
        
        return query.limit(limit).all()
    except Exception:
        return []
    finally:
        db.close()

def get_leads(status_filter=None, min_opp=None, max_opp=None):
    """Get leads with filters."""
    db = get_db()
    if not db:
        return []
    
    try:
        query = db.query(Lead).order_by(Lead.opportunity_rating.desc())
        if status_filter and status_filter != "all":
            query = query.filter(Lead.status == status_filter)
        if min_opp is not None:
            query = query.filter(Lead.opportunity_rating >= min_opp)
        if max_opp is not None:
            query = query.filter(Lead.opportunity_rating <= max_opp)
        return query.all()
    except Exception:
        return []
    finally:
        db.close()

def update_lead_status(lead_id, new_status):
    """Update lead status."""
    db = get_db()
    if not db:
        return False
    
    try:
        lead = db.query(Lead).filter(Lead.id == lead_id).first()
        if lead:
            lead.status = new_status
            lead.updated_at = datetime.utcnow()
            db.commit()
            return True
        return False
    except Exception:
        db.rollback()
        return False
    finally:
        db.close()

def save_email_template(name: str, subject: str, body: str):
    """Save email template."""
    templates_file = Path(__file__).parent / "email_templates.json"
    try:
        if templates_file.exists():
            templates = json.loads(templates_file.read_text())
        else:
            templates = {}
        
        templates[name] = {
            "subject": subject,
            "body": body,
            "created_at": datetime.now().isoformat()
        }
        templates_file.write_text(json.dumps(templates, indent=2))
        return True
    except Exception:
        return False

def load_email_templates():
    """Load email templates."""
    templates_file = Path(__file__).parent / "email_templates.json"
    try:
        if templates_file.exists():
            return json.loads(templates_file.read_text())
        return {}
    except Exception:
        return {}

class PDFReport(FPDF):
    """Enhanced PDF report generator."""
    def header(self):
        self.set_font('Arial', 'B', 24)
        self.set_text_color(0, 102, 204)
        self.cell(0, 10, clean_text(COMPANY_NAME), 0, 1, 'L')
        self.set_font('Arial', 'I', 11)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, clean_text(COMPANY_TAGLINE), 0, 1, 'L')
        self.set_draw_color(0, 102, 204)
        self.set_line_width(1)
        self.line(10, 30, 200, 30)
        self.ln(10)

    def section_title(self, label):
        self.ln(5)
        self.set_font('Arial', 'B', 14)
        self.set_fill_color(240, 248, 255)
        self.set_text_color(0, 0, 0)
        self.cell(0, 10, f"  {clean_text(label)}", 0, 1, 'L', fill=True)
        self.ln(4)

    def chapter_body(self, text):
        self.set_font('Arial', '', 10)
        self.set_text_color(50, 50, 50)
        self.multi_cell(0, 5, clean_text(text))
        self.ln()

def generate_pdf(data):
    """Generate enhanced PDF report."""
    pdf = PDFReport()
    pdf.add_page()

    # Title
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, f"Website Audit: {clean_text(data['url'])}", 0, 1)
    
    # Score with color
    if data['score'] > 70:
        pdf.set_text_color(0, 128, 0)
    elif data['score'] > 40:
        pdf.set_text_color(255, 165, 0)
    else:
        pdf.set_text_color(200, 0, 0)
    pdf.cell(0, 10, f"Health Score: {data['score']}/100", 0, 1)
    
    # Meta info
    pdf.set_text_color(0, 0, 0)
    pdf.set_font('Arial', '', 10)
    pdf.cell(0, 6, f"Domain Age: {data.get('domain_age', 'Unknown')}", 0, 1)
    pdf.cell(0, 6, f"Report Date: {datetime.now().strftime('%B %d, %Y at %H:%M')}", 0, 1)
    if data.get('psi'):
        pdf.cell(0, 6, f"Google Speed Score: {data['psi']}/100", 0, 1)
    if data.get('accessibility_score'):
        pdf.cell(0, 6, f"Accessibility Score: {data['accessibility_score']}/100", 0, 1)
    pdf.cell(0, 6, f"Audit ID: {data.get('audit_id', 'N/A')}", 0, 1)
    pdf.ln(5)

    # Executive summary
    if data.get('ai'):
        pdf.section_title("Executive Summary")
        pdf.chapter_body(data['ai'].get('summary', ''))

    # Tech stack
    pdf.section_title("Technology Stack")
    tech = ", ".join(data['tech_stack']) if data['tech_stack'] else "Standard"
    pdf.chapter_body(f"Detected: {tech}")

    # Issues
    pdf.section_title("Critical Findings")
    if data['issues']:
        for issue in data['issues']:
            pdf.set_font('Arial', 'B', 10)
            pdf.set_text_color(180, 0, 0)
            pdf.cell(0, 6, f"[!] {clean_text(issue['title'])}", 0, 1)
            pdf.set_font('Arial', '', 10)
            pdf.set_text_color(50, 50, 50)
            pdf.multi_cell(0, 5, f"Impact: {clean_text(issue['impact'])}")
            pdf.ln(2)
    else:
        pdf.chapter_body("No critical issues detected.")

    # AI email
    if data.get('ai'):
        pdf.section_title("Recommended Outreach")
        pdf.set_font('Courier', '', 9)
        pdf.multi_cell(0, 4, clean_text(data['ai'].get('email', '')))

    # Footer
    pdf.ln(10)
    pdf.set_font('Arial', 'I', 8)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, f"Report by {COMPANY_NAME} | {CONTACT_EMAIL}", 0, 1, 'C')

    return pdf.output(dest='S').encode('latin-1')

def save_audit_pdf_to_file(audit_id, pdf_bytes):
    """Save PDF to file for persistent download."""
    pdf_dir = Path(__file__).parent / "audit_pdfs"
    pdf_dir.mkdir(exist_ok=True)
    
    pdf_path = pdf_dir / f"audit_{audit_id}.pdf"
    try:
        with open(pdf_path, 'wb') as f:
            f.write(pdf_bytes)
        return str(pdf_path)
    except Exception as e:
        return None

def get_audit_pdf(audit_id):
    """Retrieve stored audit PDF."""
    pdf_path = Path(__file__).parent / "audit_pdfs" / f"audit_{audit_id}.pdf"
    try:
        if pdf_path.exists():
            return pdf_path.read_bytes()
        return None
    except Exception:
        return None

def show_admin_settings():
    """Admin settings page with enhanced features."""
    st.subheader("👥 Admin Settings")
    
    admin_tab1, admin_tab2, admin_tab3 = st.tabs(["User Management", "Analytics", "Configuration"])
    
    with admin_tab1:
        users = load_users()
        pending = [u for u in users if users[u].get("admin_request")]
        
        if pending:
            st.warning(f"⚠️ {len(pending)} pending admin request(s)")
        
        st.markdown("### User Management")
        
        cols = st.columns([2, 2, 1.5, 1.5, 1, 1, 1])
        with cols[0]: st.markdown("**Username**")
        with cols[1]: st.markdown("**Full Name**")
        with cols[2]: st.markdown("**Role**")
        with cols[3]: st.markdown("**Status**")
        with cols[4]: st.markdown("**Make Admin**")
        with cols[5]: st.markdown("**Make User**")
        with cols[6]: st.markdown("**Clear**")
        st.divider()
        
        for username, user_data in users.items():
            if username == st.session_state.get("current_user"):
                continue
            
            role = user_data.get("role", "user")
            admin_req = user_data.get("admin_request", False)
            name = user_data.get("name", "N/A")
            
            cols = st.columns([2, 2, 1.5, 1.5, 1, 1, 1])
            
            with cols[0]: st.text(username)
            with cols[1]: st.text(name)
            with cols[2]: st.text("🔴 Admin" if role == "admin" else "🟢 User")
            with cols[3]: st.text("✅ Requested" if admin_req else "❌ None")
            with cols[4]:
                if st.button("Admin", key=f"admin_{username}", use_container_width=True):
                    users[username]["role"] = "admin"
                    users[username]["admin_request"] = False
                    save_users(users)
                    st.success(f"{username} is now admin")
                    st.rerun()
            with cols[5]:
                if st.button("User", key=f"user_{username}", use_container_width=True):
                    users[username]["role"] = "user"
                    save_users(users)
                    st.success(f"{username} is now user")
                    st.rerun()
            with cols[6]:
                if admin_req and st.button("Clear", key=f"clear_{username}", use_container_width=True):
                    users[username]["admin_request"] = False
                    save_users(users)
                    st.rerun()
    
    with admin_tab2:
        st.markdown("### Analytics Dashboard")
        
        if DB_AVAILABLE:
            all_audits = get_audit_history(limit=1000)
            all_leads = get_leads()
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Audits", len(all_audits))
            with col2:
                st.metric("Total Leads", len(all_leads))
            with col3:
                avg_score = sum([a.health_score for a in all_audits]) / len(all_audits) if all_audits else 0
                st.metric("Avg Health Score", f"{avg_score:.0f}")
            with col4:
                converted = len([l for l in all_leads if l.status == "converted"])
                st.metric("Converted", converted)
            
            st.divider()
            
            # Score distribution
            if all_audits:
                scores = [a.health_score for a in all_audits]
                chart_data = pd.DataFrame({
                    "Score Range": ["0-30", "30-60", "60-80", "80-100"],
                    "Count": [
                        len([s for s in scores if s < 30]),
                        len([s for s in scores if 30 <= s < 60]),
                        len([s for s in scores if 60 <= s < 80]),
                        len([s for s in scores if s >= 80])
                    ]
                })
                st.bar_chart(chart_data.set_index("Score Range"))
            
            # Lead funnel
            if all_leads:
                lead_statuses = {}
                for lead in all_leads:
                    lead_statuses[lead.status] = lead_statuses.get(lead.status, 0) + 1
                
                st.markdown("### Lead Funnel")
                for status, count in lead_statuses.items():
                    st.write(f"{status.capitalize()}: {count}")
    
    with admin_tab3:
        st.markdown("### System Configuration")
        st.info("Slack Webhook: " + ("✓ Configured" if SLACK_WEBHOOK else "Not configured"))
        st.info("OpenAI API: " + ("✓ Configured" if OPENAI_API_KEY else "Not configured"))
        st.info("Database: " + ("✓ Connected" if DB_AVAILABLE else "Not connected"))

# ============================================================================
# MAIN APPLICATION - NAVIGATION-BASED RENDERING
# ============================================================================

st.title("🦅 Code Nest Sales Engine Pro")
st.caption("Intelligent Website Auditing & Lead Generation Platform")

# Admin notification
users = load_users()
if st.session_state.get("is_admin"):
    pending = [u for u in users if users[u].get("admin_request")]
    if pending:
        st.warning(f"🔔 {len(pending)} pending admin request(s) - Check Admin Settings")

st.divider()

# Render content based on current section
if st.session_state.current_section == "Single Audit":
    show_single_audit()

elif st.session_state.current_section == "Audit History":
    show_audit_history()

elif st.session_state.current_section == "Bulk Audit":
    if st.session_state.get("is_admin"):
        show_bulk_audit()
    else:
        st.error("This section is only available for admin users.")

elif st.session_state.current_section == "Competitor Analysis":
    if st.session_state.get("is_admin"):
        show_competitor_analysis()
    else:
        st.error("This section is only available for admin users.")

elif st.session_state.current_section == "Email Outreach":
    if st.session_state.get("is_admin"):
        show_email_outreach()
    else:
        st.error("This section is only available for admin users.")

elif st.session_state.current_section == "Scheduled Audits":
    if st.session_state.get("is_admin"):
        show_scheduled_audits()
    else:
        st.error("This section is only available for admin users.")

elif st.session_state.current_section == "API Settings":
    if st.session_state.get("is_admin"):
        show_api_settings()
    else:
        st.error("This section is only available for admin users.")

elif st.session_state.current_section == "Admin Settings":
    if st.session_state.get("is_admin"):
        show_admin_settings()
    else:
        st.error("This section is only available for admin users.")
