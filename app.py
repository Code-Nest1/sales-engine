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
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from io import BytesIO
from cryptography.fernet import Fernet
import logging
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional: 2FA support
try:
    import pyotp
    import qrcode
    TWO_FA_AVAILABLE = True
except ImportError:
    TWO_FA_AVAILABLE = False

# Load environment variables
load_dotenv()
from models import init_db, get_db, Audit, Lead, EmailOutreach, DATABASE_URL, User, BulkScan

# ============================================================================
# ENHANCED APP CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="Code Nest Sales Engine Pro",
    layout="wide",
    page_icon="🦅",
    initial_sidebar_state="expanded"
)

# Initialize theme preferences early
if 'user_theme' not in st.session_state:
    st.session_state.user_theme = 'light'

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
# LOGGING SYSTEM
# ============================================================================

# Configure logging
LOGS_DIR = Path(__file__).parent / "logs"
LOGS_DIR.mkdir(exist_ok=True)

def setup_logging():
    """Configure rotating file logger."""
    logger = logging.getLogger("sales_engine")

    if logger.hasHandlers():
        return logger

    logger.setLevel(logging.DEBUG)

    # Rotating file handler (max 5MB per file, keep 5 backups)
    handler = RotatingFileHandler(
        LOGS_DIR / "app.log",
        maxBytes=5_000_000,
        backupCount=5
    )

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger

logger = setup_logging()

# ============================================================================
# INPUT VALIDATION & SANITIZATION
# ============================================================================

def validate_url(url: str) -> tuple[bool, str]:
    """Validate URL format. Returns (is_valid, error_message)."""
    if not url or not isinstance(url, str):
        return False, "URL cannot be empty"

    url = url.strip()
    if len(url) > 2000:
        return False, "URL is too long (max 2000 characters)"

    try:
        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False, "Invalid URL format"

        # Check for valid domain
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', result.netloc):
            return False, "Invalid domain name"

        return True, ""
    except Exception as e:
        logger.warning(f"URL validation error for '{url}': {str(e)}")
        return False, f"URL validation failed: {str(e)}"

def validate_email(email: str) -> tuple[bool, str]:
    """Validate email format. Returns (is_valid, error_message)."""
    if not email or not isinstance(email, str):
        return False, "Email cannot be empty"

    email = email.strip()
    if len(email) > 254:
        return False, "Email is too long"

    # Basic email regex pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if re.match(pattern, email):
        return True, ""
    else:
        return False, "Invalid email format"

def validate_password(password: str) -> tuple[bool, str]:
    """Validate password strength. Returns (is_valid, error_message)."""
    if not password:
        return False, "Password cannot be empty"

    if len(password) < 8:
        return False, "Password must be at least 8 characters"

    if len(password) > 128:
        return False, "Password is too long"

    # Check for complexity (optional but recommended)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)

    complexity_score = sum([has_upper, has_lower, has_digit, has_special])

    if complexity_score < 3:
        return False, "Password should contain uppercase, lowercase, numbers, and special characters"

    return True, ""

def sanitize_input(user_input: str, max_length: int = 1000) -> str:
    """Sanitize user input by removing dangerous characters."""
    if not isinstance(user_input, str):
        return ""

    # Limit length
    sanitized = user_input[:max_length]

    # Remove null bytes
    sanitized = sanitized.replace('\x00', '')

    # Remove control characters except newlines and tabs
    sanitized = ''.join(char for char in sanitized if ord(char) >= 32 or char in '\n\t')

    return sanitized.strip()

def safe_execute(func, *args, default_return=None, error_message: str = "Operation failed", **kwargs):
    """Execute function safely with error handling. Returns (success, result)."""
    try:
        result = func(*args, **kwargs)
        logger.debug(f"Successfully executed {func.__name__}")
        return True, result
    except Exception as e:
        logger.error(f"Error in {func.__name__}: {str(e)}", exc_info=True)
        return False, default_return

# ============================================================================
# PERFORMANCE OPTIMIZATION - CACHING & PAGINATION
# ============================================================================

# Caching configuration
CACHE_TTL = 300  # 5 minutes cache for database queries

@st.cache_data(ttl=CACHE_TTL)
def get_audit_history_cached(limit=100, search_query=None, min_score=None, max_score=None):
    """Cached version of audit history query."""
    return get_audit_history(limit=limit, search_query=search_query, min_score=min_score, max_score=max_score)

@st.cache_data(ttl=CACHE_TTL)
def get_leads_cached():
    """Cached version of leads query."""
    return get_leads()

@st.cache_data(ttl=CACHE_TTL)
def get_scheduled_audits_cached():
    """Cached version of scheduled audits query."""
    return get_scheduled_audits() if DB_AVAILABLE else []

# Pagination helper functions
def init_pagination_state(page_key: str, items_per_page: int = 50):
    """Initialize pagination state in session."""
    if page_key not in st.session_state:
        st.session_state[page_key] = 0

def get_paginated_items(items: list, page_key: str, items_per_page: int = 50) -> tuple[list, int, int]:
    """Get paginated items. Returns (items_on_page, total_pages, current_page)."""
    init_pagination_state(page_key, items_per_page)

    total_items = len(items)
    total_pages = (total_items + items_per_page - 1) // items_per_page

    current_page = st.session_state[page_key]
    # Ensure current page is valid
    if current_page >= total_pages and total_pages > 0:
        current_page = total_pages - 1

    start_idx = current_page * items_per_page
    end_idx = start_idx + items_per_page

    return items[start_idx:end_idx], total_pages, current_page

def display_pagination_controls(page_key: str, total_pages: int, current_page: int):
    """Display pagination controls (previous/next buttons and page info)."""
    if total_pages <= 1:
        return

    col1, col2, col3, col4, col5 = st.columns([1, 1, 2, 1, 1])

    with col1:
        if st.button("◀ Prev", key=f"{page_key}_prev", use_container_width=True):
            if current_page > 0:
                st.session_state[page_key] -= 1
                st.rerun()

    with col2:
        # Page number selector
        page_selector = st.number_input(
            "Page",
            min_value=1,
            max_value=total_pages,
            value=current_page + 1,
            key=f"{page_key}_select",
            label_visibility="collapsed"
        )
        if page_selector - 1 != current_page:
            st.session_state[page_key] = page_selector - 1
            st.rerun()

    with col3:
        st.markdown(f"<p style='text-align: center; margin-top: 8px;'>Page {current_page + 1} of {total_pages}</p>", unsafe_allow_html=True)

    with col4:
        st.markdown("")  # Spacer

    with col5:
        if st.button("Next ▶", key=f"{page_key}_next", use_container_width=True):
            if current_page < total_pages - 1:
                st.session_state[page_key] += 1
                st.rerun()

# ============================================================================
# PHASE 4: EMAIL NOTIFICATIONS SYSTEM
# ============================================================================

EMAIL_CONFIG_PATH = Path(__file__).parent / "email_config.json"
NOTIFICATIONS_LOG_PATH = Path(__file__).parent / "notifications.json"

def init_email_config():
    """Initialize email configuration file with Hostinger SMTP settings."""
    if not EMAIL_CONFIG_PATH.exists():
        default_config = {
            "enabled": True,
            "smtp_server": "smtp.hostinger.com",
            "smtp_port": 587,
            "sender_email": "contact@codenest.com",
            "sender_password": os.environ.get("EMAIL_PASSWORD", ""),  # Set via environment variable
            "from_name": "Code Nest - Digital Audits",
            "auto_send_reports": True,
            "reply_to": "contact@codenest.com",
            "notifications": {
                "audit_complete": True,
                "report_sent": True,
                "permission_change": True,
                "admin_alert": True
            }
        }
        EMAIL_CONFIG_PATH.write_text(json.dumps(default_config, indent=2))
        return default_config
    try:
        return json.loads(EMAIL_CONFIG_PATH.read_text())
    except Exception:
        return init_email_config()

def load_email_config():
    """Load email configuration."""
    return init_email_config()

def save_email_config(config):
    """Save email configuration."""
    try:
        EMAIL_CONFIG_PATH.write_text(json.dumps(config, indent=2))
        return True, "Configuration saved successfully"
    except Exception as e:
        return False, f"Error saving configuration: {str(e)}"

def send_email(recipient_email, subject, html_body):
    """Send email notification with error handling."""
    try:
        config = load_email_config()

        if not config.get("enabled"):
            return False, "Email notifications are disabled"

        if not config.get("smtp_server") or not config.get("sender_email"):
            return False, "Email configuration incomplete"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{config['from_name']} <{config['sender_email']}>"
        msg["To"] = recipient_email

        part = MIMEText(html_body, "html")
        msg.attach(part)

        server = smtplib.SMTP(config["smtp_server"], config["smtp_port"], timeout=10)
        server.starttls()
        server.login(config["sender_email"], config["sender_password"])
        server.sendmail(config["sender_email"], recipient_email, msg.as_string())
        server.quit()

        log_notification(recipient_email, subject, "sent")
        logger.info(f"Email sent to {recipient_email}: {subject}")
        return True, "Email sent successfully"
    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP authentication failed")
        return False, "Authentication failed - check credentials"
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error: {str(e)}")
        return False, f"Email service error: {str(e)}"
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}")
        return False, f"Error: {str(e)}"

def log_notification(recipient, subject, status):
    """Log sent notifications."""
    try:
        if not NOTIFICATIONS_LOG_PATH.exists():
            notifications = []
        else:
            notifications = json.loads(NOTIFICATIONS_LOG_PATH.read_text())

        notifications.append({
            "timestamp": datetime.now().isoformat(),
            "recipient": recipient,
            "subject": subject,
            "status": status
        })

        # Keep only last 1000 notifications
        notifications = notifications[-1000:]
        NOTIFICATIONS_LOG_PATH.write_text(json.dumps(notifications, indent=2))
    except Exception as e:
        logger.error(f"Error logging notification: {str(e)}")

def extract_email_from_data(data):
    """Extract contact email from audit data (from OpenAI analysis)."""
    try:
        # Check if OpenAI data contains contact info
        if data.get('ai') and isinstance(data['ai'], dict):
            # Look for email in various fields that OpenAI might return
            ai_data = data['ai']

            # Check direct email field
            if ai_data.get('contact_email'):
                email = ai_data.get('contact_email')
                if validate_email(email):
                    return email

            # Check if email is embedded in other fields
            for field in ['summary', 'recommendations', 'contact_info']:
                if field in ai_data:
                    text = ai_data[field]
                    if isinstance(text, str):
                        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
                        if emails:
                            for email in emails:
                                # Exclude common system emails
                                if not any(x in email for x in ['noreply', 'no-reply', 'donotreply']):
                                    if validate_email(email):
                                        return email

        return None
    except Exception as e:
        logger.error(f"Error extracting email from data: {str(e)}")
        return None

def send_audit_report_email(recipient_email, audit_data):
    """Send audit report to website owner/contact."""
    try:
        if not recipient_email or not validate_email(recipient_email):
            logger.warning(f"Invalid email address: {recipient_email}")
            return False, "Invalid email address"

        config = load_email_config()

        if not config.get("auto_send_reports"):
            logger.info(f"Auto-send reports disabled, skipping email to {recipient_email}")
            return False, "Auto-send reports disabled"

        if not config.get("enabled"):
            return False, "Email notifications are disabled"

        if not config.get("smtp_server") or not config.get("sender_email"):
            return False, "Email configuration incomplete"

        # Extract domain from URL
        domain = urlparse(audit_data.get('url', '')).netloc.replace('www.', '')
        score = audit_data.get('score', 'N/A')

        # Build email subject and body
        subject = f"Website Audit Report - {domain} ({score}/100)"

        html_body = f"""
        <html>
            <head>
                <style>
                    body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #333; line-height: 1.6; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: linear-gradient(135deg, #0066CC 0%, #004499 100%); color: white; padding: 30px; border-radius: 5px 5px 0 0; text-align: center; }}
                    .header h1 {{ margin: 0; font-size: 28px; }}
                    .header p {{ margin: 10px 0 0 0; font-size: 14px; opacity: 0.9; }}
                    .metrics {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px; margin: 20px 0; }}
                    .metric {{ background: #f5f5f5; padding: 15px; border-radius: 5px; text-align: center; border-left: 4px solid #0066CC; }}
                    .metric-value {{ font-size: 24px; font-weight: bold; color: #0066CC; }}
                    .metric-label {{ font-size: 12px; color: #666; margin-top: 5px; text-transform: uppercase; }}
                    .section {{ margin: 25px 0; }}
                    .section-title {{ font-size: 18px; font-weight: bold; color: #0066CC; border-bottom: 2px solid #0066CC; padding-bottom: 10px; margin-bottom: 15px; }}
                    .issues-list {{ margin-top: 15px; }}
                    .issue {{ background: #fff3cd; border-left: 4px solid #ff9800; padding: 12px; margin: 10px 0; border-radius: 3px; }}
                    .issue-title {{ font-weight: bold; color: #ff6600; }}
                    .cta-button {{ display: inline-block; background: #0066CC; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
                    .footer {{ text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🎯 Website Audit Report</h1>
                        <p>Comprehensive Technical Analysis for {domain}</p>
                    </div>

                    <div style="padding: 30px; border: 1px solid #eee; border-top: none;">
                        <p>Hello,</p>
                        <p>We've completed a comprehensive technical audit of your website. Here's what we found:</p>

                        <div class="metrics">
                            <div class="metric">
                                <div class="metric-value">{score}</div>
                                <div class="metric-label">Health Score</div>
                            </div>
                            <div class="metric">
                                <div class="metric-value">{audit_data.get('psi', 'N/A')}</div>
                                <div class="metric-label">Speed Score</div>
                            </div>
                            <div class="metric">
                                <div class="metric-value">{len(audit_data.get('issues', []))}</div>
                                <div class="metric-label">Issues Found</div>
                            </div>
                        </div>

                        <div class="section">
                            <div class="section-title">⚠️ Top Issues Detected</div>
                            <div class="issues-list">
        """

        # Add top 5 issues
        for issue in audit_data.get('issues', [])[:5]:
            html_body += f"""
                                <div class="issue">
                                    <div class="issue-title">{issue.get('title', 'Unknown Issue')}</div>
                                    <p><strong>Impact:</strong> {issue.get('impact', 'N/A')}</p>
                                    <p><strong>Solution:</strong> {issue.get('solution', 'N/A')}</p>
                                </div>
            """

        html_body += """
                            </div>
                        </div>

                        <div class="section">
                            <div class="section-title">🤖 AI Analysis Summary</div>
        """

        if audit_data.get('ai'):
            html_body += f"""
                            <p><strong>Summary:</strong></p>
                            <p>{audit_data['ai'].get('summary', 'No summary available')}</p>
                            <p><strong>Recommendations:</strong></p>
                            <p>{audit_data['ai'].get('solutions', 'No recommendations available')}</p>
            """

        html_body += f"""
                        </div>

                        <center>
                            <a href="{audit_data.get('url', '#')}" class="cta-button">View Detailed Report</a>
                        </center>

                        <div class="section">
                            <p><strong>Next Steps:</strong></p>
                            <ul>
                                <li>Review the recommendations above</li>
                                <li>Prioritize high-impact issues</li>
                                <li>Contact us for implementation support</li>
                            </ul>
                        </div>

                        <div class="footer">
                            <p>Code Nest | Digital Solutions & Audits</p>
                            <p>© 2025 Code Nest. All rights reserved.</p>
                            <p>Questions? Reply to this email or contact us at contact@codenest.com</p>
                        </div>
                    </div>
                </div>
            </body>
        </html>
        """

        # Send email
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{config['from_name']} <{config['sender_email']}>"
        msg["To"] = recipient_email
        msg["Reply-To"] = config.get('reply_to', config['sender_email'])

        part = MIMEText(html_body, "html")
        msg.attach(part)

        # Send via Hostinger SMTP
        server = smtplib.SMTP(config["smtp_server"], config["smtp_port"], timeout=10)
        server.starttls()
        server.login(config["sender_email"], config["sender_password"])
        server.sendmail(config["sender_email"], recipient_email, msg.as_string())
        server.quit()

        log_notification(recipient_email, subject, "sent")
        logger.info(f"Audit report email sent to {recipient_email} for domain {domain}")

        return True, f"Report sent successfully to {recipient_email}"

    except smtplib.SMTPAuthenticationError:
        logger.error(f"SMTP authentication failed for {recipient_email}")
        return False, "Authentication failed - check email credentials"
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error sending to {recipient_email}: {str(e)}")
        return False, f"Email service error: {str(e)}"
    except Exception as e:
        logger.error(f"Error sending audit report to {recipient_email}: {str(e)}")
        return False, f"Error: {str(e)}"

def get_email_template(template_type, data):
    """Generate HTML email templates."""
    if template_type == "audit_complete":
        return f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #333;">
                <h2>Audit Completed! ✅</h2>
                <p>Hello {data.get('username', 'User')},</p>
                <p>Your audit for <strong>{data.get('domain', 'N/A')}</strong> has been completed.</p>
                <div style="background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p><strong>Score:</strong> {data.get('score', 'N/A')}/100</p>
                    <p><strong>Status:</strong> {data.get('status', 'N/A')}</p>
                    <p><strong>Completed:</strong> {data.get('timestamp', 'N/A')}</p>
                </div>
                <p>Log in to view detailed results and recommendations.</p>
                <p>Best regards,<br>Code Nest Sales Engine</p>
            </body>
        </html>
        """
    elif template_type == "permission_change":
        return f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #333;">
                <h2>Permission Update 🔐</h2>
                <p>Hello {data.get('username', 'User')},</p>
                <p>Your account permissions have been updated.</p>
                <div style="background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p><strong>New Role:</strong> {data.get('role', 'N/A')}</p>
                    <p><strong>Changed:</strong> {data.get('timestamp', 'N/A')}</p>
                </div>
                <p>If this wasn't you, please contact support immediately.</p>
                <p>Best regards,<br>Code Nest Sales Engine</p>
            </body>
        </html>
        """
    elif template_type == "admin_alert":
        return f"""
        <html>
            <body style="font-family: Arial, sans-serif; color: #333;">
                <h2>Admin Alert ⚠️</h2>
                <p>An important event has occurred:</p>
                <div style="background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p><strong>Event:</strong> {data.get('event', 'N/A')}</p>
                    <p><strong>Details:</strong> {data.get('details', 'N/A')}</p>
                    <p><strong>Time:</strong> {data.get('timestamp', 'N/A')}</p>
                </div>
                <p>Log in to the admin panel for more information.</p>
                <p>Best regards,<br>Code Nest Sales Engine</p>
            </body>
        </html>
        """

# ============================================================================
# PHASE 4: ANALYTICS DASHBOARD WITH CHARTS
# ============================================================================

def get_dashboard_analytics():
    """Compile analytics data for dashboard."""
    try:
        audits = get_audit_history_cached(limit=1000)
        if not audits:
            return None

        df = pd.DataFrame(audits)

        analytics = {
            "total_audits": len(audits),
            "avg_score": df["score"].mean() if "score" in df.columns else 0,
            "high_issue_count": len([a for a in audits if a.get("issue_count", 0) > 10]),
            "audits_by_day": df.groupby(df["timestamp"].str[:10]).size() if "timestamp" in df.columns else {},
            "score_distribution": pd.cut(df["score"], bins=[0, 25, 50, 75, 100]).value_counts() if "score" in df.columns else {},
            "top_issues": get_top_issues(audits),
            "latest_audits": audits[:5]
        }
        return analytics
    except Exception as e:
        logger.error(f"Error compiling analytics: {str(e)}")
        return None

def get_top_issues(audits, limit=10):
    """Get most common issues found."""
    try:
        issue_count = {}
        for audit in audits:
            if "issues" in audit and isinstance(audit["issues"], list):
                for issue in audit["issues"][:5]:  # Take top 5 per audit
                    issue_count[issue] = issue_count.get(issue, 0) + 1

        return sorted(issue_count.items(), key=lambda x: x[1], reverse=True)[:limit]
    except Exception:
        return []

def show_dashboard():
    """Display analytics dashboard."""
    st.markdown("## 📊 Analytics Dashboard")

    analytics = get_dashboard_analytics()
    if not analytics:
        st.warning("No audit data available yet. Complete some audits first!")
        return

    # KPI Metrics
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Total Audits",
            analytics["total_audits"],
            delta=None,
            help="Total number of audits completed"
        )

    with col2:
        avg_score = round(analytics["avg_score"], 1)
        st.metric(
            "Average Score",
            f"{avg_score}/100",
            delta=None,
            help="Average health score across all audits"
        )

    with col3:
        st.metric(
            "High Issue Sites",
            analytics["high_issue_count"],
            delta=None,
            help="Sites with 10+ issues found"
        )

    # Charts
    st.divider()

    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.markdown("### Audits Over Time (Last 30 Days)")
        if analytics["audits_by_day"]:
            try:
                import plotly.express as px
                df_days = pd.DataFrame({
                    "Date": list(analytics["audits_by_day"].keys()),
                    "Count": list(analytics["audits_by_day"].values())
                })
                fig = px.line(df_days, x="Date", y="Count", markers=True,
                            title="", labels={"Count": "Audits"})
                st.plotly_chart(fig, use_container_width=True)
            except Exception as e:
                st.error(f"Error creating chart: {str(e)}")
        else:
            st.info("No recent audit data")

    with col_chart2:
        st.markdown("### Score Distribution")
        if analytics["score_distribution"].size > 0:
            try:
                import plotly.express as px
                dist_data = analytics["score_distribution"].reset_index()
                dist_data.columns = ["Range", "Count"]
                fig = px.bar(dist_data, x="Range", y="Count",
                           title="", labels={"Count": "Number of Sites"})
                st.plotly_chart(fig, use_container_width=True)
            except Exception as e:
                st.error(f"Error creating chart: {str(e)}")
        else:
            st.info("No score distribution data")

    # Top Issues
    st.divider()
    st.markdown("### Top 10 Issues Found")
    if analytics["top_issues"]:
        issue_df = pd.DataFrame(analytics["top_issues"], columns=["Issue", "Occurrences"])
        st.dataframe(issue_df, use_container_width=True)
    else:
        st.info("No issue data available yet")

# ============================================================================
# PHASE 4: PDF & EXCEL EXPORT REPORTS
# ============================================================================

def generate_pdf_report(audit_data, filename="audit_report.pdf"):
    """Generate professional PDF report for an audit with complete details."""
    try:
        pdf = FPDF()
        pdf.add_page()

        # Header
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Code Nest Sales Engine - Audit Report", ln=True, align="C")
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 5, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        pdf.ln(5)

        # Audit Details
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, "Audit Summary", ln=True)
        pdf.set_font("Arial", "", 10)

        details = [
            ("Domain", audit_data.get("domain", audit_data.get("url", "N/A"))),
            ("Health Score", f"{audit_data.get('score', audit_data.get('health_score', 'N/A'))}/100"),
            ("Page Speed Score", str(audit_data.get('psi', audit_data.get('psi_score', 'N/A')))),
            ("Domain Age", str(audit_data.get('domain_age', 'N/A'))),
            ("Date", audit_data.get('timestamp', audit_data.get('created_at', 'N/A'))),
        ]

        for label, value in details:
            pdf.set_font("Arial", "", 10)
            pdf.cell(50, 6, f"{label}:", 0)
            pdf.set_font("Arial", "B", 10)
            pdf.cell(0, 6, str(value)[:50], ln=True)

        pdf.ln(5)

        # Tech Stack
        if "tech_stack" in audit_data and audit_data["tech_stack"]:
            pdf.set_font("Arial", "B", 11)
            pdf.cell(0, 7, "Technology Stack", ln=True)
            pdf.set_font("Arial", "", 9)
            tech_text = ", ".join(audit_data["tech_stack"][:15])
            pdf.multi_cell(0, 4, tech_text)
            pdf.ln(3)

        # Issues
        if "issues" in audit_data and audit_data["issues"]:
            pdf.set_font("Arial", "B", 11)
            pdf.cell(0, 7, f"Issues Found ({len(audit_data['issues'])})", ln=True)
            pdf.set_font("Arial", "", 9)

            for i, issue in enumerate(audit_data["issues"][:15], 1):
                issue_text = str(issue)[:80]
                pdf.multi_cell(0, 4, f"{i}. {issue_text}")
            pdf.ln(2)

        # Emails Found
        if "emails" in audit_data and audit_data["emails"]:
            pdf.set_font("Arial", "B", 11)
            pdf.cell(0, 7, "Contact Emails", ln=True)
            pdf.set_font("Arial", "", 10)
            for email in audit_data["emails"][:5]:
                pdf.cell(0, 5, f"• {email}", ln=True)
            pdf.ln(2)

        # AI Insights
        if "ai" in audit_data and audit_data["ai"]:
            ai_data = audit_data["ai"]

            if ai_data.get("summary"):
                pdf.set_font("Arial", "B", 11)
                pdf.cell(0, 7, "AI Summary", ln=True)
                pdf.set_font("Arial", "", 9)
                pdf.multi_cell(0, 4, str(ai_data.get("summary", ""))[:400])
                pdf.ln(2)

            if ai_data.get("impact"):
                pdf.set_font("Arial", "B", 11)
                pdf.cell(0, 7, "Business Impact", ln=True)
                pdf.set_font("Arial", "", 9)
                pdf.multi_cell(0, 4, str(ai_data.get("impact", ""))[:400])
                pdf.ln(2)

            if ai_data.get("solutions"):
                pdf.set_font("Arial", "B", 11)
                pdf.cell(0, 7, "Recommended Solutions", ln=True)
                pdf.set_font("Arial", "", 9)
                pdf.multi_cell(0, 4, str(ai_data.get("solutions", ""))[:400])
                pdf.ln(2)

            if ai_data.get("email"):
                pdf.set_font("Arial", "B", 11)
                pdf.cell(0, 7, "AI Email Draft", ln=True)
                pdf.set_font("Arial", "", 8)
                pdf.multi_cell(0, 3, str(ai_data.get("email", ""))[:600])
                pdf.ln(2)

        # Footer
        pdf.ln(5)
        pdf.set_font("Arial", "I", 8)
        pdf.cell(0, 5, "© 2025 Code Nest. All rights reserved. | www.codenest.dev", align="C")

        # Save to bytes
        pdf_bytes = pdf.output(dest='S').encode('latin-1')
        return pdf_bytes
    except Exception as e:
        logger.error(f"Error generating PDF: {str(e)}")
        return None

def generate_excel_report(audits, filename="audits_report.xlsx"):
    """Generate Excel report with multiple sheets."""
    try:
        import openpyxl
        from openpyxl.styles import Font, PatternFill, Alignment

        # Create workbook
        from io import BytesIO
        output = BytesIO()

        df = pd.DataFrame(audits)

        # Write to Excel
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            # Sheet 1: Summary
            summary_data = {
                "Metric": ["Total Audits", "Average Score", "Highest Score", "Lowest Score"],
                "Value": [
                    len(audits),
                    round(df["score"].mean(), 2) if "score" in df.columns else "N/A",
                    df["score"].max() if "score" in df.columns else "N/A",
                    df["score"].min() if "score" in df.columns else "N/A"
                ]
            }
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)

            # Sheet 2: All Audits
            df.to_excel(writer, sheet_name='Audits', index=False)

        output.seek(0)
        return output
    except Exception as e:
        logger.error(f"Error generating Excel: {str(e)}")
        return None

# ============================================================================
# PHASE 4: DARK MODE SUPPORT
# ============================================================================

def init_theme_preferences():
    """Initialize theme preferences file."""
    theme_path = Path(__file__).parent / "theme_prefs.json"
    if not theme_path.exists():
        theme_path.write_text(json.dumps({"theme": "light"}, indent=2))
    return theme_path

def get_user_theme(username):
    """Get user's theme preference."""
    try:
        theme_path = init_theme_preferences()
        prefs = json.loads(theme_path.read_text())
        return prefs.get("theme", "light")
    except Exception:
        return "light"

def save_user_theme(username, theme):
    """Save user's theme preference."""
    try:
        theme_path = init_theme_preferences()
        prefs = json.loads(theme_path.read_text()) if theme_path.exists() else {}
        prefs["theme"] = theme
        theme_path.write_text(json.dumps(prefs, indent=2))
        return True
    except Exception:
        return False

def apply_theme(theme="light"):
    """Apply theme via CSS."""
    if theme == "dark":
        st.markdown("""
        <style>
            :root {
                --primary-color: #3B82F6;
                --bg-color: #111827;
                --text-color: #F3F4F6;
                --border-color: #374151;
            }
            body {
                background-color: #111827;
                color: #F3F4F6;
            }
            .stButton > button {
                background-color: #3B82F6;
                color: white;
            }
            .stMetric {
                background-color: #1F2937;
                padding: 10px;
                border-radius: 5px;
            }
        </style>
        """, unsafe_allow_html=True)

# ============================================================================
# PHASE 4: USER PREFERENCES & SETTINGS PANEL
# ============================================================================

PREFERENCES_PATH = Path(__file__).parent / "user_preferences.json"

def init_preferences_file():
    """Initialize user preferences file."""
    if not PREFERENCES_PATH.exists():
        PREFERENCES_PATH.write_text(json.dumps({}, indent=2))

def load_user_preferences(username):
    """Load user preferences."""
    try:
        init_preferences_file()
        prefs = json.loads(PREFERENCES_PATH.read_text())
        return prefs.get(username, {
            "theme": "light",
            "notifications_enabled": True,
            "notification_frequency": "weekly",
            "items_per_page": 50,
            "timezone": "UTC",
            "language": "en"
        })
    except Exception:
        return {}

def save_user_preferences(username, preferences):
    """Save user preferences."""
    try:
        init_preferences_file()
        prefs = json.loads(PREFERENCES_PATH.read_text())
        prefs[username] = preferences
        PREFERENCES_PATH.write_text(json.dumps(prefs, indent=2))
        return True, "Preferences saved successfully"
    except Exception as e:
        return False, f"Error saving preferences: {str(e)}"

def show_preferences_panel(username):
    """Display user preferences panel."""
    st.markdown("## ⚙️ User Preferences")

    # Load current preferences
    prefs = load_user_preferences(username)

    # Create tabs for different settings
    tab1, tab2, tab3, tab4 = st.tabs(["Display", "Notifications", "Account", "Privacy"])

    with tab1:
        st.markdown("### Display Settings")
        new_theme = st.selectbox(
            "Theme",
            ["light", "dark", "auto"],
            index=["light", "dark", "auto"].index(prefs.get("theme", "light"))
        )

        new_items_per_page = st.slider(
            "Items per page",
            min_value=10,
            max_value=100,
            value=prefs.get("items_per_page", 50),
            step=10
        )

        new_language = st.selectbox(
            "Language",
            ["English", "Spanish", "French", "German"],
            index=0 if prefs.get("language", "en") == "en" else 1
        )

    with tab2:
        st.markdown("### Notification Settings")
        notifications_enabled = st.checkbox(
            "Enable email notifications",
            value=prefs.get("notifications_enabled", True)
        )

        notification_frequency = st.selectbox(
            "Notification frequency",
            ["immediately", "daily", "weekly", "monthly"],
            index=["immediately", "daily", "weekly", "monthly"].index(prefs.get("notification_frequency", "weekly"))
        )

        st.markdown("**Notify me for:**")
        col1, col2, col3 = st.columns(3)
        with col1:
            audit_complete = st.checkbox("Audit completion", value=True)
        with col2:
            permission_change = st.checkbox("Permission changes", value=True)
        with col3:
            admin_alerts = st.checkbox("Admin alerts", value=True)

    with tab3:
        st.markdown("### Account Settings")
        if st.button("Change Password", use_container_width=True):
            st.session_state.show_password_change = True

        if st.button("View Login History", use_container_width=True):
            st.session_state.show_login_history = True

        if st.checkbox("Enable Two-Factor Authentication", value=False):
            st.info("Two-factor authentication is enabled for your account.")

    with tab4:
        st.markdown("### Privacy Settings")
        data_retention = st.selectbox(
            "Data retention",
            ["30 days", "90 days", "1 year", "indefinite"],
            index=2
        )

        api_key_visible = st.checkbox("Show API key in plain text", value=False)

        if st.button("Download My Data", use_container_width=True):
            st.info("Your data will be downloaded as a JSON file.")

        if st.button("Delete Account", use_container_width=True, help="This action cannot be undone"):
            st.warning("⚠️ This will permanently delete your account and all associated data.")

    # Save button
    if st.button("Save Preferences", use_container_width=True, type="primary"):
        updated_prefs = {
            "theme": new_theme if 'new_theme' in locals() else prefs.get("theme", "light"),
            "notifications_enabled": notifications_enabled if 'notifications_enabled' in locals() else prefs.get("notifications_enabled", True),
            "notification_frequency": notification_frequency if 'notification_frequency' in locals() else prefs.get("notification_frequency", "weekly"),
            "items_per_page": new_items_per_page if 'new_items_per_page' in locals() else prefs.get("items_per_page", 50),
            "timezone": prefs.get("timezone", "UTC"),
            "language": new_language if 'new_language' in locals() else prefs.get("language", "en")
        }
        success, message = save_user_preferences(username, updated_prefs)
        if success:
            st.success(message)
        else:
            st.error(message)

# ============================================================================
# AUTHENTICATION & USER MANAGEMENT
# ============================================================================

USERS_PATH = Path(__file__).parent / "users.json"
TWO_FA_PATH = Path(__file__).parent / "two_fa.json"
SESSIONS_PATH = Path(__file__).parent / "sessions.json"
LOGIN_ATTEMPTS_PATH = Path(__file__).parent / "login_attempts.json"
ENCRYPTION_KEY_PATH = Path(__file__).parent / ".encryption_key"
SESSION_TIMEOUT_HOURS = 168  # 7 days
LOGIN_ATTEMPT_LIMIT = 5
LOGIN_ATTEMPT_WINDOW_MINUTES = 5

def init_users_file():
    """Create users.json if it doesn't exist."""
    if not USERS_PATH.exists():
        USERS_PATH.write_text(json.dumps({"users": {}}, indent=2))

def init_2fa_file():
    """Create two_fa.json if it doesn't exist."""
    if not TWO_FA_PATH.exists():
        TWO_FA_PATH.write_text(json.dumps({}, indent=2))

def get_encryption_key() -> bytes:
    """Get or create encryption key for API keys."""
    if ENCRYPTION_KEY_PATH.exists():
        return ENCRYPTION_KEY_PATH.read_bytes()
    else:
        key = Fernet.generate_key()
        ENCRYPTION_KEY_PATH.write_bytes(key)
        return key

def init_login_attempts_file():
    """Create login_attempts.json if it doesn't exist."""
    if not LOGIN_ATTEMPTS_PATH.exists():
        LOGIN_ATTEMPTS_PATH.write_text(json.dumps({}, indent=2))

def load_login_attempts():
    """Load login attempts tracking."""
    init_login_attempts_file()
    try:
        return json.loads(LOGIN_ATTEMPTS_PATH.read_text())
    except Exception:
        return {}

def save_login_attempts(attempts: dict):
    """Save login attempts tracking."""
    LOGIN_ATTEMPTS_PATH.write_text(json.dumps(attempts, indent=2))

def check_login_rate_limit(username: str) -> tuple[bool, str]:
    """Check if user is rate limited. Returns (allowed, message)."""
    attempts = load_login_attempts()
    now = datetime.now()

    if username not in attempts:
        attempts[username] = []

    # Remove attempts older than the window
    attempts[username] = [
        attempt for attempt in attempts[username]
        if datetime.fromisoformat(attempt) > now - timedelta(minutes=LOGIN_ATTEMPT_WINDOW_MINUTES)
    ]

    if len(attempts[username]) >= LOGIN_ATTEMPT_LIMIT:
        return False, f"Too many login attempts. Please try again in {LOGIN_ATTEMPT_WINDOW_MINUTES} minutes."

    return True, ""

def record_login_attempt(username: str):
    """Record a failed login attempt."""
    attempts = load_login_attempts()

    if username not in attempts:
        attempts[username] = []

    attempts[username].append(datetime.now().isoformat())
    save_login_attempts(attempts)

def clear_login_attempts(username: str):
    """Clear login attempts on successful login."""
    attempts = load_login_attempts()
    if username in attempts:
        attempts[username] = []
        save_login_attempts(attempts)

def init_sessions_file():
    """Create sessions.json if it doesn't exist."""
    if not SESSIONS_PATH.exists():
        SESSIONS_PATH.write_text(json.dumps({}, indent=2))

def load_sessions():
    """Load active sessions."""
    init_sessions_file()
    try:
        return json.loads(SESSIONS_PATH.read_text())
    except Exception:
        return {}

def save_sessions(sessions: dict):
    """Save active sessions."""
    SESSIONS_PATH.write_text(json.dumps(sessions, indent=2))

def create_session(username: str, role: str) -> str:
    """Create a new session and return session token."""
    import uuid

    session_token = uuid.uuid4().hex[:32]
    sessions = load_sessions()

    sessions[session_token] = {
        "username": username,
        "role": role,
        "created_at": datetime.now().isoformat(),
        "last_access": datetime.now().isoformat()
    }
    save_sessions(sessions)

    # Also store in browser via query parameter (Streamlit workaround)
    st.session_state['session_token'] = session_token

    return session_token

def validate_session(session_token: str) -> dict:
    """Validate session token and return user info if valid. Checks for timeout."""
    sessions = load_sessions()

    if session_token in sessions:
        session_data = sessions[session_token]

        # Check if session has expired
        created_at = datetime.fromisoformat(session_data["created_at"])
        if datetime.now() - created_at > timedelta(hours=SESSION_TIMEOUT_HOURS):
            # Session expired, remove it
            del sessions[session_token]
            save_sessions(sessions)
            return None

        # Update last access time
        session_data["last_access"] = datetime.now().isoformat()
        sessions[session_token] = session_data
        save_sessions(sessions)
        return session_data

    return None

def destroy_session(session_token: str):
    """Destroy a session."""
    sessions = load_sessions()
    if session_token in sessions:
        del sessions[session_token]
        save_sessions(sessions)

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

def get_user_api_permissions(username: str) -> dict:
    """Get API permissions for a user."""
    users = load_users()
    if username not in users:
        return {"openai": False, "google": False, "slack": False}

    return users[username].get("api_permissions", {"openai": False, "google": False, "slack": False})

def set_user_api_permission(username: str, api_key: str, enabled: bool):
    """Set API permission for a user."""
    users = load_users()
    if username not in users:
        return False

    if "api_permissions" not in users[username]:
        users[username]["api_permissions"] = {"openai": False, "google": False, "slack": False}

    users[username]["api_permissions"][api_key] = enabled
    save_users(users)
    return True

def check_user_api_access(username: str, api_key: str) -> bool:
    """Check if user has access to specific API."""
    perms = get_user_api_permissions(username)
    return perms.get(api_key, False)

def encrypt_key(key: str) -> str:
    """Encrypt API key using Fernet (secure encryption)."""
    cipher = Fernet(get_encryption_key())
    return cipher.encrypt(key.encode()).decode()

def decrypt_key(encrypted_key: str) -> str:
    """Decrypt API key using Fernet."""
    try:
        cipher = Fernet(get_encryption_key())
        return cipher.decrypt(encrypted_key.encode()).decode()
    except:
        return ""

def get_user_api_keys(username: str) -> dict:
    """Get API keys for a user from database."""
    try:
        db = get_db()
        if not db:
            return {"openai": "", "google": "", "slack": ""}

        user = db.query(User).filter(User.username == username).first()
        if not user:
            return {"openai": "", "google": "", "slack": ""}

        api_keys = user.api_keys or {}
        # Decrypt keys when retrieving - always return all three keys
        decrypted = {"openai": "", "google": "", "slack": ""}
        for key_name, encrypted_value in api_keys.items():
            try:
                decrypted[key_name] = decrypt_key(encrypted_value)
            except:
                decrypted[key_name] = ""

        db.close()
        return decrypted
    except Exception as e:
        logger = logging.getLogger("sales_engine")
        logger.error(f"Error loading API keys for {username}: {str(e)}")
        return {"openai": "", "google": "", "slack": ""}

def save_user_api_key(username: str, key_name: str, key_value: str):
    """Save API key for a user to database (encrypted)."""
    try:
        db = get_db()
        if not db:
            return False

        user = db.query(User).filter(User.username == username).first()
        if not user:
            db.close()
            return False

        if not user.api_keys:
            user.api_keys = {}

        # Encrypt key before saving
        user.api_keys[key_name] = encrypt_key(key_value)
        user.api_keys_updated_at = datetime.utcnow()

        # Force SQLAlchemy to detect the change in JSON column
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(user, "api_keys")

        db.commit()
        db.close()
        return True
    except Exception as e:
        logger = logging.getLogger("sales_engine")
        logger.error(f"Error saving API key for {username}: {str(e)}")
        if db:
            db.close()
        return False

def delete_user_api_key(username: str, key_name: str):
    """Delete API key for a user from database."""
    try:
        db = get_db()
        if not db:
            return False

        user = db.query(User).filter(User.username == username).first()
        if not user:
            db.close()
            return False

        if user.api_keys and key_name in user.api_keys:
            del user.api_keys[key_name]
            user.api_keys_updated_at = datetime.utcnow()

            # Force SQLAlchemy to detect the change in JSON column
            from sqlalchemy.orm.attributes import flag_modified
            flag_modified(user, "api_keys")

            db.commit()
            db.close()
            return True

        db.close()
        return False
    except Exception as e:
        logger = logging.getLogger("sales_engine")
        logger.error(f"Error deleting API key for {username}: {str(e)}")
        if db:
            db.close()
        return False

def migrate_api_keys_from_json_to_db():
    """Migrate API keys from users.json to database (one-time migration)."""
    logger = logging.getLogger("sales_engine")
    try:
        users_json = load_users()
        db = get_db()
        if not db:
            return

        for username, user_data in users_json.items():
            if "api_keys" in user_data and user_data["api_keys"]:
                # Find or create user in database
                db_user = db.query(User).filter(User.username == username).first()
                if db_user:
                    # Only migrate if database user doesn't have keys yet
                    if not db_user.api_keys:
                        db_user.api_keys = user_data["api_keys"]
                        db_user.api_keys_updated_at = datetime.utcnow()
                        db.commit()
                        logger.info(f"Migrated API keys for user: {username}")

        db.close()
    except Exception as e:
        logger.error(f"Error during API key migration: {str(e)}")

def ensure_user_in_database(username: str, password_hash: str, is_admin: bool = False):
    """Ensure a user exists in the database (called during login for JSON-only users)."""
    logger = logging.getLogger("sales_engine")
    try:
        db = get_db()
        if not db:
            return False

        # Check if user already exists in database
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            db.close()
            return True

        # Create new user in database
        new_user = User(
            username=username,
            password_hash=password_hash,
            is_admin=is_admin
        )
        db.add(new_user)
        db.commit()
        db.close()
        logger.info(f"Synced JSON user to database: {username}")
        return True
    except Exception as e:
        logger.error(f"Error syncing user {username} to database: {str(e)}")
        if db:
            db.close()
        return False

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

def reload_user_api_keys():
    """Reload API keys from database (called after login or session restore)."""
    if st.session_state.get("current_user"):
        user_keys = get_user_api_keys(st.session_state.get("current_user"))

        # Check environment variables first (highest priority)
        env_openai = os.environ.get("OPENAI_API_KEY")
        env_google = os.environ.get("GOOGLE_API_KEY")
        env_slack = os.environ.get("SLACK_WEBHOOK")

        # Set from env or user account (env overrides user keys)
        st.session_state.OPENAI_API_KEY = env_openai or user_keys.get("openai", "")
        st.session_state.GOOGLE_API_KEY = env_google or user_keys.get("google", "")
        st.session_state.SLACK_WEBHOOK = env_slack or user_keys.get("slack", "")

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
            else:
                # Check rate limiting
                allowed, message = check_login_rate_limit(username)
                if not allowed:
                    st.error(message)
                elif username not in users:
                    record_login_attempt(username)
                    st.error("User not found")
                elif not verify_password(password, users[username]["password_hash"]):
                    record_login_attempt(username)
                    st.error("Invalid credentials")
                else:
                    # Successful login - clear attempts
                    clear_login_attempts(username)

                    # Ensure user exists in database (for users who only exist in JSON)
                    user_role = users[username].get("role", "user")
                    ensure_user_in_database(username, users[username]["password_hash"], is_admin=(user_role == "admin"))

                    # Check if 2FA is enabled
                    secrets_2fa = load_2fa_secrets()
                    if username in secrets_2fa and secrets_2fa[username].get("enabled"):
                        st.session_state["2fa_pending"] = True
                        st.session_state["2fa_username"] = username
                        st.rerun()
                    else:
                        # Create persistent session
                        session_token = create_session(username, user_role)
                        st.experimental_set_query_params(session_token=session_token)
                        st.session_state["authenticated"] = True
                        st.session_state["current_user"] = username
                        st.session_state["is_admin"] = user_role == "admin"
                        st.session_state["user_role"] = user_role

                        # Reload API keys from user account after login
                        reload_user_api_keys()

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
                    # Create persistent session
                    username_2fa = st.session_state["2fa_username"]
                    user_role = users[username_2fa].get("role", "user")

                    # Ensure user exists in database (for users who only exist in JSON)
                    ensure_user_in_database(username_2fa, users[username_2fa]["password_hash"], is_admin=(user_role == "admin"))

                    session_token = create_session(username_2fa, user_role)
                    st.experimental_set_query_params(session_token=session_token)
                    st.session_state["authenticated"] = True
                    st.session_state["current_user"] = username_2fa
                    st.session_state["is_admin"] = user_role == "admin"
                    st.session_state["user_role"] = user_role
                    st.session_state["2fa_pending"] = False

                    # Reload API keys from user account after login
                    reload_user_api_keys()

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
            # Sanitize inputs
            full_name_clean = sanitize_input(full_name, max_length=100)
            username_clean = sanitize_input(username, max_length=50)
            reason_clean = sanitize_input(reason, max_length=500) if reason else ""

            # Validate fields
            if not full_name_clean or not username_clean or not password:
                st.error("❌ All fields are required")
                logger.warning(f"Signup attempt with missing fields")
            elif password != confirm:
                st.error("❌ Passwords don't match")
                logger.warning(f"Signup attempt: password mismatch for {username_clean}")
            elif username_clean in users:
                st.error("❌ Username already taken")
                logger.warning(f"Signup attempt with existing username: {username_clean}")
            else:
                # Validate password strength
                is_valid, pwd_error = validate_password(password)
                if not is_valid:
                    st.error(f"❌ Password requirements: {pwd_error}")
                    logger.warning(f"Weak password attempt for {username_clean}")
                else:
                    # Validate username format
                    if not re.match(r'^[a-zA-Z0-9_]{3,50}$', username_clean):
                        st.error("❌ Username must be 3-50 characters, alphanumeric + underscore only")
                        logger.warning(f"Invalid username format: {username_clean}")
                    else:
                        try:
                            users[username_clean] = {
                                "name": full_name_clean,
                                "password_hash": hash_password(password),
                                "role": "user",
                                "admin_request": request_admin,
                                "admin_request_reason": reason_clean,
                                "created_at": datetime.now().isoformat(),
                                "last_login": None
                            }
                            save_users(users)

                            # Also create user in database
                            if DB_AVAILABLE:
                                try:
                                    db = get_db()
                                    if db:
                                        new_user = User(
                                            username=username_clean,
                                            password_hash=hash_password(password),
                                            is_admin=(request_admin and "admin" in reason_clean.lower())
                                        )
                                        db.add(new_user)
                                        db.commit()
                                        db.close()
                                        logger.info(f"New database user created: {username_clean}")
                                except Exception as e:
                                    logger.error(f"Error creating database user for {username_clean}: {str(e)}")

                            logger.info(f"New account created: {username_clean}")
                            st.success("✅ Account created! Please login.")
                            time.sleep(1)
                            st.rerun()
                        except Exception as e:
                            logger.error(f"Error creating account for {username_clean}: {str(e)}", exc_info=True)
                            st.error("❌ Failed to create account. Please try again.")
# Initialize auth
init_users_file()
init_2fa_file()
init_sessions_file()
init_login_attempts_file()

# Initialize encryption key (will be created if not exists)
get_encryption_key()

# Migrate API keys from JSON to database (one-time operation)
if not st.session_state.get("_api_keys_migrated"):
    migrate_api_keys_from_json_to_db()
    st.session_state["_api_keys_migrated"] = True

# Initialize authentication state first
if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False
    st.session_state['current_user'] = None
    st.session_state['is_admin'] = False
    st.session_state['user_role'] = 'user'
    st.session_state['2fa_pending'] = False
    st.session_state['2fa_username'] = None

# --- Try to restore session from query params ---
query_params = st.experimental_get_query_params()
if 'session_token' in query_params:
    try:
        token = query_params['session_token'][0]
        session_info = validate_session(token)
        if session_info:
            st.session_state['session_token'] = token
            st.session_state['authenticated'] = True
            st.session_state['current_user'] = session_info['username']
            st.session_state['is_admin'] = session_info['role'] == 'admin'
            st.session_state['user_role'] = session_info['role']
            st.session_state['2fa_pending'] = False
            st.session_state['2fa_username'] = None

            # Reload API keys from user account after session restore
            reload_user_api_keys()
    except Exception as e:
        pass  # Session token invalid or expired, continue to login page

# Check authentication
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
# IMPORTANT: Always reload from database if user is logged in to ensure fresh data

if st.session_state.get("current_user"):
    # User is logged in - always reload from database to ensure we have latest keys
    user_keys = get_user_api_keys(st.session_state.get("current_user"))

    # Check environment variables first (highest priority)
    env_openai = os.environ.get("OPENAI_API_KEY")
    env_google = os.environ.get("GOOGLE_API_KEY")
    env_slack = os.environ.get("SLACK_WEBHOOK")

    # Set from env or user account (env overrides user keys)
    st.session_state.OPENAI_API_KEY = env_openai or user_keys.get("openai", "")
    st.session_state.GOOGLE_API_KEY = env_google or user_keys.get("google", "")
    st.session_state.SLACK_WEBHOOK = env_slack or user_keys.get("slack", "")
else:
    # User is not logged in - initialize from environment variables only
    if 'OPENAI_API_KEY' not in st.session_state:
        st.session_state.OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")

    if 'GOOGLE_API_KEY' not in st.session_state:
        st.session_state.GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "")

    if 'SLACK_WEBHOOK' not in st.session_state:
        st.session_state.SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK", "")

# Get current API keys from session
OPENAI_API_KEY = st.session_state.OPENAI_API_KEY
GOOGLE_API_KEY = st.session_state.GOOGLE_API_KEY
SLACK_WEBHOOK = st.session_state.SLACK_WEBHOOK

with st.sidebar:
    st.header("🦅 Code Nest Panel")
    st.caption("Navigation")
    st.divider()

    # Build navigation items based on role
    nav_items = ["Single Audit", "Audit History", "Dashboard", "Preferences"]
    if st.session_state.get("is_admin"):
        nav_items.extend([
            "Bulk Audit",
            "Competitor Analysis",
            "Lead Management",
            "Email Outreach",
            "Scheduled Audits",
            "API Settings",
            "Admin Settings",
            "Email Settings",
            "Export Reports"
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
        # Destroy session token
        if 'session_token' in st.session_state:
            destroy_session(st.session_state['session_token'])
            del st.session_state['session_token']

        # Clear authentication
        st.session_state['authenticated'] = False
        st.session_state['current_user'] = None
        st.session_state['is_admin'] = False
        st.session_state['user_role'] = 'user'
        st.session_state.current_section = 'Single Audit'
        st.session_state['2fa_pending'] = False
        st.session_state['2fa_username'] = None

        # Clear query params to remove session token from URL
        st.experimental_set_query_params()
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
    """API Settings page for configuring API keys securely."""
    st.title("🔑 API Settings")
    st.markdown("Securely manage your API keys for AI email generation, PageSpeed insights, and Slack notifications")
    st.markdown("---")

    username = st.session_state.get("current_user", "")
    if not username:
        st.warning("Please log in to access API settings")
        return

    # Get current user's API keys
    current_keys = get_user_api_keys(username)

    # Custom CSS for API settings cards
    st.markdown("""
    <style>
    .api-key-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 12px;
        color: white;
        margin-bottom: 15px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    .api-key-status {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 15px;
        padding-bottom: 10px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.2);
    }
    .api-key-name {
        font-size: 16px;
        font-weight: bold;
    }
    .api-key-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: bold;
    }
    .badge-active {
        background-color: rgba(100, 200, 100, 0.8);
        color: white;
    }
    .badge-inactive {
        background-color: rgba(255, 107, 107, 0.8);
        color: white;
    }
    .api-controls {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 10px;
        margin-top: 15px;
    }
    .api-toggle {
        background-color: rgba(255, 255, 255, 0.15);
        padding: 10px;
        border-radius: 8px;
        border: 1px solid rgba(255, 255, 255, 0.2);
        text-align: center;
    }
    .api-toggle.enabled {
        background-color: rgba(100, 200, 100, 0.3);
        border-color: rgba(100, 200, 100, 0.6);
    }
    .api-label {
        font-size: 12px;
        font-weight: bold;
        margin-bottom: 5px;
    }
    .actions {
        display: flex;
        gap: 8px;
        margin-top: 15px;
        flex-wrap: wrap;
    }
    .btn-action {
        flex: 1;
        min-width: 100px;
        padding: 8px 12px;
        border-radius: 6px;
        border: none;
        font-size: 12px;
        font-weight: bold;
        cursor: pointer;
        transition: all 0.3s ease;
    }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("### 📊 User Management & API Access Control")
    st.markdown("Manage user roles and control their API access permissions below:")
    st.divider()

    # Filter users
    col1, col2 = st.columns(2)
    with col1:
            filter_role = st.selectbox("Filter by Role", ["All", "Admin", "User"])
    with col2:
            search_user = st.text_input("Search username")

    # Display users
    for username, user_data in users.items():
            if username == st.session_state.get("current_user"):
                continue

            role = user_data.get("role", "user")
            admin_req = user_data.get("admin_request", False)
            name = user_data.get("name", "N/A")

            # Apply filters
            if filter_role != "All" and role.capitalize() != filter_role:
                continue
            if search_user and search_user.lower() not in username.lower():
                continue

            # Get API permissions
            api_perms = get_user_api_permissions(username)

            # Beautiful user card
            with st.container():
                col1, col2 = st.columns([2, 1])

                with col1:
                    st.markdown(f"""
                    <div class="user-card">
                        <div class="user-header">
                            <div>
                                <div class="user-name">👤 {name}</div>
                                <div style="font-size: 12px; opacity: 0.8;">@{username}</div>
                            </div>
                            <div class="user-role role-{'admin' if role == 'admin' else 'user'}">
                                {'👑 ADMIN' if role == 'admin' else '👤 USER'}
                            </div>
                        </div>

                        <div class="api-controls">
                            <div class="api-toggle {'enabled' if api_perms['openai'] else ''}">
                                <div class="api-label">🤖 OpenAI</div>
                                <div style="font-size: 11px;">{'✅ Enabled' if api_perms['openai'] else '❌ Disabled'}</div>
                            </div>
                            <div class="api-toggle {'enabled' if api_perms['google'] else ''}">
                                <div class="api-label">🔍 Google</div>
                                <div style="font-size: 11px;">{'✅ Enabled' if api_perms['google'] else '❌ Disabled'}</div>
                            </div>
                            <div class="api-toggle {'enabled' if api_perms['slack'] else ''}">
                                <div class="api-label">📱 Slack</div>
                                <div style="font-size: 11px;">{'✅ Enabled' if api_perms['slack'] else '❌ Disabled'}</div>
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                with col2:
                    # Action buttons
                    st.markdown("**Actions:**")

                    # Role management (using selectbox instead of buttons)
                    new_role = st.selectbox(
                        "Role",
                        ["user", "admin"],
                        index=0 if role == "user" else 1,
                        key=f"role_{username}"
                    )

                    if new_role != role:
                        users[username]["role"] = new_role
                        if new_role == "admin":
                            users[username]["admin_request"] = False
                        save_users(users)
                        st.toast(f"✓ {username} role updated to {new_role}")

                    # Clear admin requests
                    if admin_req:
                        if st.button("❌ Clear Admin Request", key=f"clear_{username}", use_container_width=True):
                            users[username]["admin_request"] = False
                            save_users(users)
                            st.toast(f"Request cleared for {username}")

                # API Access Control Section with form
                st.markdown("**⚙️ API Access Control:**")

                with st.form(key=f"api_form_{username}", clear_on_submit=False):
                    col_api1, col_api2, col_api3 = st.columns(3)

                    with col_api1:
                        openai_access = st.checkbox(
                            "🤖 Allow OpenAI",
                            value=api_perms.get("openai", False),
                            key=f"openai_{username}"
                        )

                    with col_api2:
                        google_access = st.checkbox(
                            "🔍 Allow Google PageSpeed",
                            value=api_perms.get("google", False),
                            key=f"google_{username}"
                        )

                    with col_api3:
                        slack_access = st.checkbox(
                            "📱 Allow Slack",
                            value=api_perms.get("slack", False),
                            key=f"slack_{username}"
                        )

                    # Submit button for form (no rerun)
                    submitted = st.form_submit_button("💾 Save API Permissions", use_container_width=True)
                    if submitted:
                        set_user_api_permission(username, "openai", openai_access)
                        set_user_api_permission(username, "google", google_access)
                        set_user_api_permission(username, "slack", slack_access)
                        st.toast(f"✓ API permissions saved for {username}")

                st.divider()

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

def show_email_settings():
    """Configure email notification settings."""
    st.markdown("## 📧 Email Notification Settings")

    # Hostinger setup info
    with st.expander("📋 Hostinger SMTP Setup Guide", expanded=False):
        st.markdown("""
        ### Quick Setup for Hostinger Email

        **SMTP Configuration for Hostinger:**
        - **SMTP Server:** `smtp.hostinger.com`
        - **SMTP Port:** `587` (TLS) or `465` (SSL)
        - **Sender Email:** Your Hostinger email (e.g., `contact@codenest.com`)
        - **Password:** Your Hostinger email password

        **Steps to get your credentials:**
        1. Log in to Hostinger Control Panel
        2. Go to **Email** → Your email account
        3. Find SMTP/IMAP settings
        4. Copy the SMTP server address and your email credentials

        **Alternative - Using Environment Variable:**
        ```bash
        # Set this in your .env file for security:
        EMAIL_PASSWORD=your_hostinger_email_password
        ```

        **Auto-Send Reports Feature:**
        - When you run an audit, the system will automatically try to:
          1. Extract contact email from OpenAI analysis
          2. Send a formatted audit report to that email
          3. Log all sent emails for tracking

        **Email Features:**
        - ✅ Automatic report sending when contacts are found
        - ✅ Professional HTML formatted emails
        - ✅ Includes audit metrics, top issues, and recommendations
        - ✅ All emails logged and tracked
        - ✅ Manual send with custom email addresses
        """)

    config = load_email_config()

    st.markdown("### SMTP Configuration")

    col1, col2 = st.columns(2)
    with col1:
        enabled = st.checkbox("Enable Email Notifications", value=config.get("enabled", False))
    with col2:
        auto_send = st.checkbox("Auto-Send Reports", value=config.get("auto_send_reports", True), help="Automatically send reports when emails are found")

    with st.form("email_config_form"):
        smtp_server = st.text_input(
            "SMTP Server",
            value=config.get("smtp_server", ""),
            placeholder="e.g., smtp.gmail.com",
            help="Your email provider's SMTP server address"
        )

        smtp_port = st.number_input(
            "SMTP Port",
            value=config.get("smtp_port", 587),
            min_value=1,
            max_value=65535,
            help="Usually 587 for TLS or 465 for SSL"
        )

        sender_email = st.text_input(
            "Sender Email Address",
            value=config.get("sender_email", ""),
            placeholder="noreply@example.com"
        )

        sender_password = st.text_input(
            "Email Password/App Password",
            value=config.get("sender_password", ""),
            type="password",
            help="Use an app-specific password for Gmail",
            placeholder="••••••••"
        )

        from_name = st.text_input(
            "Display Name",
            value=config.get("from_name", "Code Nest Sales Engine"),
            help="Name that appears in 'From:' field"
        )

        reply_to = st.text_input(
            "Reply-To Email Address",
            value=config.get("reply_to", config.get("sender_email", "")),
            placeholder="support@example.com",
            help="Email address for replies"
        )

        st.markdown("### Notification Types")
        col1, col2, col3 = st.columns(3)
        with col1:
            audit_notif = st.checkbox("Audit Completions", value=config.get("notifications", {}).get("audit_complete", True))
        with col2:
            perm_notif = st.checkbox("Permission Changes", value=config.get("notifications", {}).get("permission_change", True))
        with col3:
            admin_notif = st.checkbox("Admin Alerts", value=config.get("notifications", {}).get("admin_alert", True))

        # Test email
        st.markdown("### Test Configuration")
        test_email = st.text_input("Send test email to:", placeholder="test@example.com")

        col1, col2, col3 = st.columns([1, 1, 2])
        with col1:
            submit = st.form_submit_button("Save Configuration", type="primary", use_container_width=True)
        with col2:
            test = st.form_submit_button("Send Test Email", use_container_width=True)

        if submit:
            new_config = {
                "enabled": enabled,
                "smtp_server": smtp_server,
                "smtp_port": smtp_port,
                "sender_email": sender_email,
                "sender_password": sender_password,
                "from_name": from_name,
                "reply_to": reply_to,
                "auto_send_reports": auto_send,
                "notifications": {
                    "audit_complete": audit_notif,
                    "permission_change": perm_notif,
                    "admin_alert": admin_notif
                }
            }
            success, message = save_email_config(new_config)
            if success:
                st.success(message)
                st.rerun()
            else:
                st.error(message)

        if test and test_email:
            if not enabled or not smtp_server or not sender_email:
                st.error("Please configure SMTP settings and enable notifications first")
            else:
                with st.spinner("Sending test email..."):
                    html_body = get_email_template("admin_alert", {
                        "event": "Test Email",
                        "details": "This is a test email from Code Nest Sales Engine",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                    success, message = send_email(test_email, "Test Email - Code Nest Sales Engine", html_body)
                    if success:
                        st.success(f"✅ {message}")
                    else:
                        st.error(f"❌ {message}")

    # Notification logs
    st.divider()
    st.markdown("### Notification Logs")

    if NOTIFICATIONS_LOG_PATH.exists():
        try:
            notifications = json.loads(NOTIFICATIONS_LOG_PATH.read_text())
            if notifications:
                df = pd.DataFrame(notifications[-50:])  # Last 50
                df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
                st.dataframe(df.sort_values("timestamp", ascending=False), use_container_width=True)
            else:
                st.info("No notifications sent yet")
        except Exception as e:
            st.error(f"Error loading logs: {str(e)}")
    else:
        st.info("No notification logs available yet")
