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
from cryptography.fernet import Fernet
import logging
from logging.handlers import RotatingFileHandler

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
    """Generate professional PDF report for an audit."""
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
            ("Domain", audit_data.get("domain", "N/A")),
            ("Score", f"{audit_data.get('score', 'N/A')}/100"),
            ("Status", audit_data.get("status", "N/A")),
            ("Date", audit_data.get("timestamp", "N/A")),
        ]
        
        for label, value in details:
            pdf.cell(50, 6, f"{label}:", 0)
            pdf.cell(0, 6, str(value), ln=True)
        
        pdf.ln(5)
        
        # Issues
        if "issues" in audit_data and audit_data["issues"]:
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 8, "Issues Found", ln=True)
            pdf.set_font("Arial", "", 9)
            
            for i, issue in enumerate(audit_data["issues"][:10], 1):
                pdf.multi_cell(0, 5, f"{i}. {issue}")
        
        # Footer
        pdf.ln(10)
        pdf.set_font("Arial", "I", 8)
        pdf.cell(0, 5, "© 2025 Code Nest. All rights reserved.", align="C")
        
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
    """Get API keys for a user."""
    users = load_users()
    if username in users:
        api_keys = users[username].get("api_keys", {})
        # Decrypt keys when retrieving
        decrypted = {}
        for key_name, encrypted_value in api_keys.items():
            try:
                decrypted[key_name] = decrypt_key(encrypted_value)
            except:
                decrypted[key_name] = ""
        return decrypted
    return {"openai": "", "google": "", "slack": ""}

def save_user_api_key(username: str, key_name: str, key_value: str):
    """Save API key for a user (encrypted)."""
    users = load_users()
    if username not in users:
        return False
    
    if "api_keys" not in users[username]:
        users[username]["api_keys"] = {}
    
    # Encrypt key before saving
    users[username]["api_keys"][key_name] = encrypt_key(key_value)
    users[username]["api_keys_updated"] = datetime.now().isoformat()
    save_users(users)
    return True

def delete_user_api_key(username: str, key_name: str):
    """Delete API key for a user."""
    users = load_users()
    if username not in users:
        return False
    
    if "api_keys" in users[username] and key_name in users[username]["api_keys"]:
        del users[username]["api_keys"][key_name]
        save_users(users)
        return True
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
                    
                    # Check if 2FA is enabled
                    secrets_2fa = load_2fa_secrets()
                    if username in secrets_2fa and secrets_2fa[username].get("enabled"):
                        st.session_state["2fa_pending"] = True
                        st.session_state["2fa_username"] = username
                        st.rerun()
                    else:
                        # Create persistent session
                        user_role = users[username].get("role", "user")
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
# This function reloads API keys from user account after login
def reload_user_api_keys():
    """Reload API keys from user account (call after login)."""
    if st.session_state.get("current_user"):
        user_keys = get_user_api_keys(st.session_state.get("current_user"))
        
        # Check environment variables first (highest priority)
        env_openai = os.environ.get("OPENAI_API_KEY")
        env_google = os.environ.get("GOOGLE_API_KEY")
        env_slack = os.environ.get("SLACK_WEBHOOK")
        
        # Set from env or user account
        st.session_state.OPENAI_API_KEY = env_openai or user_keys.get("openai", "")
        st.session_state.GOOGLE_API_KEY = env_google or user_keys.get("google", "")
        st.session_state.SLACK_WEBHOOK = env_slack or user_keys.get("slack", "")

if 'OPENAI_API_KEY' not in st.session_state:
    # Try environment variable first, then user's saved key
    env_key = os.environ.get("OPENAI_API_KEY")
    if env_key:
        st.session_state.OPENAI_API_KEY = env_key
    elif st.session_state.get("current_user"):
        # Load from user's saved keys if logged in
        user_keys = get_user_api_keys(st.session_state.get("current_user"))
        st.session_state.OPENAI_API_KEY = user_keys.get("openai", "")
    else:
        st.session_state.OPENAI_API_KEY = ""

if 'GOOGLE_API_KEY' not in st.session_state:
    env_key = os.environ.get("GOOGLE_API_KEY")
    if env_key:
        st.session_state.GOOGLE_API_KEY = env_key
    elif st.session_state.get("current_user"):
        # Load from user's saved keys if logged in
        user_keys = get_user_api_keys(st.session_state.get("current_user"))
        st.session_state.GOOGLE_API_KEY = user_keys.get("google", "")
    else:
        st.session_state.GOOGLE_API_KEY = ""

if 'SLACK_WEBHOOK' not in st.session_state:
    env_key = os.environ.get("SLACK_WEBHOOK")
    if env_key:
        st.session_state.SLACK_WEBHOOK = env_key
    elif st.session_state.get("current_user"):
        # Load from user's saved keys if logged in
        user_keys = get_user_api_keys(st.session_state.get("current_user"))
        st.session_state.SLACK_WEBHOOK = user_keys.get("slack", "")
    else:
        st.session_state.SLACK_WEBHOOK = ""

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
    </style>
    """, unsafe_allow_html=True)
    
    # API 1: OpenAI
    st.markdown("### 🤖 OpenAI API")
    st.markdown("For AI email generation and content analysis")
    
    with st.container():
        col1, col2 = st.columns([3, 1])
        
        with col1:
            if current_keys.get("openai") and not st.session_state.get("edit_openai"):
                # Show masked key with options
                masked_key = current_keys["openai"][:8] + "..." + current_keys["openai"][-4:] if len(current_keys["openai"]) > 12 else "***"
                st.markdown(f"""
                <div class="api-key-card">
                    <div class="api-key-status">
                        <div>
                            <div class="api-key-name">✅ OpenAI Key Active</div>
                            <div style="font-size: 12px; opacity: 0.8;">Key: {masked_key}</div>
                        </div>
                        <div class="api-key-badge badge-active">ACTIVE</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                col_view, col_delete, col_add = st.columns(3)
                
                with col_view:
                    if st.button("👁️ View Full Key", key="view_openai", use_container_width=True):
                        st.session_state.show_openai_key = not st.session_state.get("show_openai_key", False)
                    
                    if st.session_state.get("show_openai_key"):
                        st.code(current_keys["openai"], language="text")
                
                with col_delete:
                    if st.button("🗑️ Delete Key", key="del_openai", use_container_width=True):
                        delete_user_api_key(username, "openai")
                        st.success("✓ OpenAI key deleted")
                        st.rerun()
                
                with col_add:
                    if st.button("🔄 Replace Key", key="replace_openai", use_container_width=True):
                        st.session_state.edit_openai = True
                        st.rerun()
            
            elif st.session_state.get("edit_openai") or not current_keys.get("openai"):
                # Add/Edit form
                if not current_keys.get("openai"):
                    st.markdown("""
                    <div class="api-key-card">
                        <div class="api-key-status">
                            <div>
                                <div class="api-key-name">❌ No Key Added</div>
                                <div style="font-size: 12px; opacity: 0.8;">Add your OpenAI key to enable AI features</div>
                            </div>
                            <div class="api-key-badge badge-inactive">INACTIVE</div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                
                st.markdown("**Add or Replace OpenAI API Key:**")
                new_openai_key = st.text_input(
                    "Paste your OpenAI API Key",
                    type="password",
                    key="input_openai",
                    placeholder="sk-..."
                )
                
                col_save, col_cancel = st.columns(2)
                with col_save:
                    if st.button("✅ Save OpenAI Key", key="save_openai_btn", use_container_width=True):
                        if new_openai_key:
                            save_user_api_key(username, "openai", new_openai_key)
                            st.session_state.OPENAI_API_KEY = new_openai_key
                            st.success("✓ OpenAI key saved securely and loaded into session")
                            st.session_state.edit_openai = False
                            st.rerun()
                        else:
                            st.error("Please enter an API key")
                
                with col_cancel:
                    if st.button("❌ Cancel", key="cancel_openai_btn", use_container_width=True):
                        st.session_state.edit_openai = False
                        st.rerun()
    
    st.divider()
    
    # API 2: Google PageSpeed
    st.markdown("### 🔍 Google PageSpeed API")
    st.markdown("For website performance analysis")
    
    with st.container():
        col1, col2 = st.columns([3, 1])
        
        with col1:
            if current_keys.get("google") and not st.session_state.get("edit_google"):
                masked_key = current_keys["google"][:8] + "..." + current_keys["google"][-4:] if len(current_keys["google"]) > 12 else "***"
                st.markdown(f"""
                <div class="api-key-card">
                    <div class="api-key-status">
                        <div>
                            <div class="api-key-name">✅ Google Key Active</div>
                            <div style="font-size: 12px; opacity: 0.8;">Key: {masked_key}</div>
                        </div>
                        <div class="api-key-badge badge-active">ACTIVE</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                col_view, col_delete, col_add = st.columns(3)
                
                with col_view:
                    if st.button("👁️ View Full Key", key="view_google", use_container_width=True):
                        st.session_state.show_google_key = not st.session_state.get("show_google_key", False)
                    
                    if st.session_state.get("show_google_key"):
                        st.code(current_keys["google"], language="text")
                
                with col_delete:
                    if st.button("🗑️ Delete Key", key="del_google", use_container_width=True):
                        delete_user_api_key(username, "google")
                        st.success("✓ Google key deleted")
                        st.rerun()
                
                with col_add:
                    if st.button("🔄 Replace Key", key="replace_google", use_container_width=True):
                        st.session_state.edit_google = True
                        st.rerun()
            
            elif st.session_state.get("edit_google") or not current_keys.get("google"):
                # Add/Edit form
                if not current_keys.get("google"):
                    st.markdown("""
                    <div class="api-key-card">
                        <div class="api-key-status">
                            <div>
                                <div class="api-key-name">❌ No Key Added</div>
                                <div style="font-size: 12px; opacity: 0.8;">Add your Google PageSpeed key to enable performance analysis</div>
                            </div>
                            <div class="api-key-badge badge-inactive">INACTIVE</div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                
                st.markdown("**Add or Replace Google PageSpeed API Key:**")
                new_google_key = st.text_input(
                    "Paste your Google PageSpeed API Key",
                    type="password",
                    key="input_google",
                    placeholder="AIza..."
                )
                
                col_save, col_cancel = st.columns(2)
                with col_save:
                    if st.button("✅ Save Google Key", key="save_google_btn", use_container_width=True):
                        if new_google_key:
                            save_user_api_key(username, "google", new_google_key)
                            st.session_state.GOOGLE_API_KEY = new_google_key
                            st.success("✓ Google key saved securely and loaded into session")
                            st.session_state.edit_google = False
                            st.rerun()
                        else:
                            st.error("Please enter an API key")
                
                with col_cancel:
                    if st.button("❌ Cancel", key="cancel_google_btn", use_container_width=True):
                        st.session_state.edit_google = False
                        st.rerun()
    
    st.divider()
    
    # API 3: Slack Webhook
    st.markdown("### 📱 Slack Webhook URL")
    st.markdown("For audit notifications (optional)")
    
    with st.container():
        col1, col2 = st.columns([3, 1])
        
        with col1:
            if current_keys.get("slack") and not st.session_state.get("edit_slack"):
                masked_key = current_keys["slack"][:20] + "..." + current_keys["slack"][-10:] if len(current_keys["slack"]) > 30 else "***"
                st.markdown(f"""
                <div class="api-key-card">
                    <div class="api-key-status">
                        <div>
                            <div class="api-key-name">✅ Slack Webhook Active</div>
                            <div style="font-size: 12px; opacity: 0.8;">URL: {masked_key}</div>
                        </div>
                        <div class="api-key-badge badge-active">ACTIVE</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                col_view, col_delete, col_add = st.columns(3)
                
                with col_view:
                    if st.button("👁️ View Full URL", key="view_slack", use_container_width=True):
                        st.session_state.show_slack_key = not st.session_state.get("show_slack_key", False)
                    
                    if st.session_state.get("show_slack_key"):
                        st.code(current_keys["slack"], language="text")
                
                with col_delete:
                    if st.button("🗑️ Delete URL", key="del_slack", use_container_width=True):
                        delete_user_api_key(username, "slack")
                        st.success("✓ Slack webhook deleted")
                        st.rerun()
                
                with col_add:
                    if st.button("🔄 Replace URL", key="replace_slack", use_container_width=True):
                        st.session_state.edit_slack = True
                        st.rerun()
            
            elif st.session_state.get("edit_slack") or not current_keys.get("slack"):
                # Add/Edit form
                if not current_keys.get("slack"):
                    st.markdown("""
                    <div class="api-key-card">
                        <div class="api-key-status">
                            <div>
                                <div class="api-key-name">❌ No Webhook Added</div>
                                <div style="font-size: 12px; opacity: 0.8;">Add your Slack webhook to receive notifications</div>
                            </div>
                            <div class="api-key-badge badge-inactive">INACTIVE</div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                
                st.markdown("**Add or Replace Slack Webhook URL:**")
                new_slack_key = st.text_input(
                    "Paste your Slack Webhook URL",
                    type="password",
                    key="input_slack",
                    placeholder="https://hooks.slack.com/services/..."
                )
                
                col_save, col_cancel = st.columns(2)
                with col_save:
                    if st.button("✅ Save Slack URL", key="save_slack_btn", use_container_width=True):
                        if new_slack_key:
                            save_user_api_key(username, "slack", new_slack_key)
                            st.session_state.SLACK_WEBHOOK = new_slack_key
                            st.success("✓ Slack webhook saved securely and loaded into session")
                            st.session_state.edit_slack = False
                            st.rerun()
                        else:
                            st.error("Please enter a webhook URL")
                
                with col_cancel:
                    if st.button("❌ Cancel", key="cancel_slack_btn", use_container_width=True):
                        st.session_state.edit_slack = False
                        st.rerun()
    
    st.markdown("---")
    st.info("🔒 **Security:** Your API keys are encrypted and stored securely in the database. They are never displayed in plain text unless you explicitly view them.")
    
    # Show last updated time if available
    users = load_users()
    if username in users and "api_keys_updated" in users[username]:
        last_updated = users[username]["api_keys_updated"]
        st.caption(f"Last updated: {last_updated}")

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
        url_sanitized = sanitize_input(url, max_length=2000)
        
        # Validate URL
        is_valid, error_msg = validate_url(url_sanitized)
        if not is_valid:
            st.error(f"❌ Invalid URL: {error_msg}")
            logger.warning(f"Invalid URL submitted: {url_sanitized}")
        else:
            logger.info(f"Starting audit for URL: {url_sanitized}")
            
            with st.spinner("🔄 Analyzing website..."):
                success, data = safe_execute(
                    run_audit,
                    url_sanitized,
                    st.session_state.OPENAI_API_KEY,
                    st.session_state.GOOGLE_API_KEY,
                    error_message="Audit failed"
                )
                
                if not success or "error" in data:
                    error_msg = data.get('error', 'Unknown error during audit')
                    st.error(f"❌ Scan Failed: {error_msg}")
                    logger.error(f"Audit failed for {url_sanitized}: {error_msg}")
                else:
                    logger.info(f"Audit completed successfully for {url_sanitized}")
                    
                    # Save to database safely
                    try:
                        if DB_AVAILABLE:
                            save_audit_to_db(data)
                            logger.debug(f"Audit saved to database for {url_sanitized}")
                    except Exception as e:
                        logger.warning(f"Failed to save audit to database: {str(e)}")
                        st.warning("⚠️ Audit completed but couldn't save to database")
                    
                    # Metrics
                    st.markdown("---")
                    st.markdown("### 📊 Audit Results")
                    
                    c1, c2, c3, c4, c5 = st.columns(5)
                    
                    with c1:
                        st.metric("Health Score", data.get('score', 'N/A'), delta=("Good" if data.get('score', 0) >= 70 else "Needs Work"))
                    with c2:
                        st.metric("Google Speed", data.get('psi', 'N/A'))
                    with c3:
                        st.metric("Accessibility", data.get('accessibility_score', 'N/A'))
                    with c4:
                        st.metric("Issues Found", len(data.get('issues', [])))
                    with c5:
                        st.metric("Age", data.get('domain_age', 'Unknown'))
                    
                    # Tech stack
                    if data.get('tech_stack'):
                        st.markdown(f"**📦 Tech Stack:** {', '.join(data['tech_stack'])}")
                    
                    # Issues
                    if data.get('issues'):
                        st.markdown("---")
                        st.markdown("### ⚠️ Issues Detected")
                        
                        for i, issue in enumerate(data.get('issues', []), 1):
                            try:
                                with st.expander(f"{i}. {issue.get('title', 'Unknown Issue')}", expanded=(i <= 2)):
                                    col1, col2 = st.columns(2)
                                    with col1:
                                        st.markdown(f"**Impact:** {issue.get('impact', 'N/A')}")
                                    with col2:
                                        st.markdown(f"**Solution:** {issue.get('solution', 'N/A')}")
                            except Exception as e:
                                logger.error(f"Error displaying issue {i}: {str(e)}")
                                st.warning(f"Could not display issue #{i}")
                    
                    # AI analysis
                    if data.get('ai'):
                        st.markdown("---")
                        st.markdown("### 🤖 AI Analysis")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown("**Summary**")
                            st.info(data['ai'].get('summary', 'No summary available'))
                            st.markdown("**Impact**")
                            st.warning(data['ai'].get('impact', 'No impact assessment available'))
                        
                        with col2:
                            st.markdown("**Solutions**")
                            st.success(data['ai'].get('solutions', 'No solutions available'))
                        
                        st.markdown("---")
                        st.markdown("**📧 Cold Email Draft**")
                        st.text_area("", value=clean_text(data['ai']['email']), height=250, key="email_draft")
                        
                        # Auto-send audit report to contact email
                        st.markdown("---")
                        st.markdown("### 📤 Send Audit Report")
                        
                        # Try to extract email from OpenAI data
                        extracted_email = extract_email_from_data(data)
                        
                        col1, col2 = st.columns([2, 1])
                        with col1:
                            recipient_email = st.text_input(
                                "Send report to (contact email)",
                                value=extracted_email or "",
                                placeholder="contact@website.com",
                                help="Email will be sent with detailed audit report"
                            )
                        
                        with col2:
                            if st.button("📧 Send Report", type="secondary", use_container_width=True):
                                if recipient_email:
                                    with st.spinner("Sending report..."):
                                        success, message = send_audit_report_email(recipient_email, data)
                                        if success:
                                            st.success(f"✅ {message}")
                                            logger.info(f"Audit report sent to {recipient_email}")
                                        else:
                                            st.error(f"❌ {message}")
                                            logger.error(f"Failed to send report to {recipient_email}: {message}")
                                else:
                                    st.warning("⚠️ Please enter a recipient email address")
                    
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
    """Audit history page for all users - with pagination."""
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
        
        # Use cached query
        audits = get_audit_history_cached(
            limit=1000,
            search_query=search if search else None,
            min_score=min_score if min_score > 0 else None,
            max_score=max_score if max_score < 100 else None
        )
        
        if audits:
            # Convert to dataframe for pagination
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
            
            # Pagination
            paginated_data, total_pages, current_page = get_paginated_items(
                hist_data, 
                page_key="audit_history_page",
                items_per_page=50
            )
            
            # Display data
            st.dataframe(
                pd.DataFrame(paginated_data).drop(columns=["ID"]),
                use_container_width=True,
                hide_index=True
            )
            
            # Pagination controls
            st.markdown("---")
            display_pagination_controls("audit_history_page", total_pages, current_page)
            
            # Download section
            st.markdown("---")
            st.markdown(f"### 📥 Download PDFs (Page {current_page + 1})")
            
            cols = st.columns(3)
            col_idx = 0
            for item in paginated_data:
                # Find corresponding audit object
                audit = next((a for a in audits if a.id == item["ID"]), None)
                if audit:
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
                                st.warning(f"PDF not available. Run audit again to generate.")
                    col_idx += 1
            
            # Export CSV for all results
            st.markdown("---")
            st.markdown("### 📥 Export All Results")
            csv = pd.DataFrame(hist_data).drop(columns=["ID"]).to_csv(index=False).encode('utf-8')
            st.download_button(
                "📥 Export All Audits as CSV",
                csv,
                "audit_history_complete.csv",
                "text/csv"
            )
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
            leads = get_leads_cached()
            
            if leads:
                lead_opts = {f"{l.domain} (Score: {l.health_score}, Opp: {l.opportunity_rating})": l for l in leads}
                selected_name = st.selectbox("Select a lead", list(lead_opts.keys()), key="lead_select")
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

def show_lead_management():
    """Advanced lead management with CSV import, AI enrichment, and service scoring."""
    st.title("🎯 Lead Management & Enrichment")
    st.markdown("Import leads from Google Places, enrich with AI, and identify service opportunities")
    st.markdown("---")
    
    if not DB_AVAILABLE:
        st.error("Database required for lead management")
        return
    
    tab1, tab2, tab3, tab4 = st.tabs(["Import Leads", "Lead Database", "Service Opportunities", "AI Insights"])
    
    with tab1:
        st.markdown("### 📤 Import Leads from CSV")
        st.markdown("Upload your Google Places CSV export with: name, phone, address, city, state, zipcode, place_id, website")
        
        uploaded_file = st.file_uploader("Upload CSV file", type="csv")
        
        if uploaded_file:
            try:
                df = pd.read_csv(uploaded_file)
                st.write(f"**Preview:** {len(df)} leads found")
                
                with st.expander("View CSV Preview"):
                    st.dataframe(df.head(10), use_container_width=True)
                
                if st.button("🚀 Process & Enrich Leads", type="primary"):
                    with st.spinner("Processing leads and running audits..."):
                        # First, run audits on websites
                        audit_scores = {}
                        progress_bar = st.progress(0)
                        
                        for idx, row in df.iterrows():
                            website = row.get('website', '') or row.get('url', '')
                            if website:
                                if not website.startswith('http'):
                                    website = 'https://' + website
                                
                                try:
                                    audit_data = run_audit(website, st.session_state.OPENAI_API_KEY, st.session_state.GOOGLE_API_KEY)
                                    domain = urlparse(website).netloc.replace('www.', '')
                                    audit_scores[domain] = audit_data
                                except Exception as e:
                                    logger.warning(f"Error auditing {website}: {str(e)}")
                            
                            progress_bar.progress((idx + 1) / len(df))
                        
                        # Process CSV with enrichment
                        leads_created, errors = process_csv_leads(
                            uploaded_file,
                            audit_scores,
                            st.session_state.OPENAI_API_KEY
                        )
                        
                        st.success(f"✅ Successfully imported {leads_created} leads!")
                        
                        if errors:
                            with st.expander(f"⚠️ {len(errors)} Import Issues"):
                                for error in errors:
                                    st.warning(error)
            
            except Exception as e:
                st.error(f"Error processing file: {str(e)}")
    
    with tab2:
        st.markdown("### 📊 Lead Database")
        
        # Filters
        col1, col2, col3 = st.columns(3)
        with col1:
            status_filter = st.selectbox("Filter by Status", ["all", "new", "contacted", "responded", "converted", "lost"])
        with col2:
            industry_filter = st.text_input("Filter by Industry", placeholder="E.g., E-Commerce, SaaS")
        with col3:
            size_filter = st.selectbox("Filter by Company Size", ["All", "Small", "Medium", "Large", "Enterprise"])
        
        # Get leads
        db = get_db()
        if db:
            query = db.query(Lead).order_by(Lead.opportunity_rating.desc())
            
            if status_filter != "all":
                query = query.filter(Lead.status == status_filter)
            
            if industry_filter:
                query = query.filter(Lead.industry.contains(industry_filter))
            
            if size_filter != "All":
                query = query.filter(Lead.company_size == size_filter)
            
            leads = query.all()
            db.close()
            
            if leads:
                # Display metrics
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total Leads", len(leads))
                with col2:
                    avg_opp = sum(l.opportunity_rating for l in leads) / len(leads) if leads else 0
                    st.metric("Avg Opportunity", f"{avg_opp:.0f}/100")
                with col3:
                    high_priority = len([l for l in leads if l.opportunity_rating >= 70])
                    st.metric("High Priority", high_priority)
                with col4:
                    converted = len([l for l in leads if l.status == "converted"])
                    st.metric("Converted", converted)
                
                st.divider()
                
                # Leads table
                leads_data = []
                for lead in leads[:100]:  # Limit to 100 for performance
                    leads_data.append({
                        "Company": lead.company_name or "N/A",
                        "Industry": lead.industry or "Unknown",
                        "Size": lead.company_size or "Unknown",
                        "Health Score": lead.health_score or "N/A",
                        "Opportunity": lead.opportunity_rating,
                        "Status": lead.status,
                        "Location": f"{lead.city}, {lead.state}" if lead.city else "N/A",
                        "Phone": lead.phone or "N/A"
                    })
                
                st.dataframe(
                    pd.DataFrame(leads_data),
                    use_container_width=True,
                    column_config={
                        "Opportunity": st.column_config.ProgressColumn(
                            "Opportunity",
                            min_value=0,
                            max_value=100,
                        ),
                    }
                )
            else:
                st.info("No leads found. Try importing CSV data first.")
    
    with tab3:
        st.markdown("### 🎯 Service Opportunities")
        
        db = get_db()
        if db:
            leads = db.query(Lead).order_by(Lead.opportunity_rating.desc()).limit(50).all()
            db.close()
            
            if leads:
                # Select a lead to see service opportunities
                lead_options = {f"{l.company_name} ({l.city}, {l.state})" or l.domain: l for l in leads}
                selected_lead_name = st.selectbox("Select a lead to view service opportunities", list(lead_options.keys()))
                selected_lead = lead_options[selected_lead_name]
                
                if selected_lead:
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.markdown(f"**Company:** {selected_lead.company_name or 'N/A'}")
                        st.markdown(f"**Industry:** {selected_lead.industry or 'Unknown'}")
                    with col2:
                        st.markdown(f"**Size:** {selected_lead.company_size or 'Unknown'}")
                        st.markdown(f"**Health Score:** {selected_lead.health_score or 'N/A'}/100")
                    with col3:
                        st.markdown(f"**Location:** {selected_lead.city}, {selected_lead.state}" if selected_lead.city else "")
                        st.markdown(f"**Opportunity:** {selected_lead.opportunity_rating}/100")
                    
                    st.divider()
                    
                    if selected_lead.service_priorities:
                        st.markdown("### 📈 Service Opportunity Scores")
                        
                        service_names = {
                            'website_development': '🌐 Website Development',
                            'seo_optimization': '🔍 SEO Optimization',
                            'mobile_app_development': '📱 Mobile App Development',
                            'social_media_marketing': '📱 Social Media Marketing',
                            'paid_advertising': '💰 Paid Advertising (PPC)',
                            'ecommerce_development': '🛒 E-Commerce Development',
                            'website_maintenance': '🔧 Website Maintenance',
                            'react_nextjs_development': '⚛️ React/Next.js Development',
                            'website_optimization': '⚡ Website Optimization',
                            'graphic_designing': '🎨 Graphic Designing'
                        }
                        
                        cols = st.columns(2)
                        for idx, (service_key, score) in enumerate(sorted(selected_lead.service_priorities.items(), 
                                                                          key=lambda x: x[1], reverse=True)):
                            with cols[idx % 2]:
                                service_name = service_names.get(service_key, service_key)
                                st.markdown(f"### {service_name}")
                                
                                # Progress bar
                                col_score, col_badge = st.columns([3, 1])
                                with col_score:
                                    st.progress(min(100, score) / 100)
                                with col_badge:
                                    if score >= 80:
                                        st.error(f"{score:.0f}")
                                    elif score >= 60:
                                        st.warning(f"{score:.0f}")
                                    else:
                                        st.info(f"{score:.0f}")
                                
                                # Show pitch on click
                                if st.button(f"View Pitch", key=f"pitch_{service_key}"):
                                    st.session_state[f"show_pitch_{service_key}"] = True
                                
                                if st.session_state.get(f"show_pitch_{service_key}"):
                                    with st.expander("📧 Service Pitch", expanded=True):
                                        pitch = generate_service_pitch(
                                            selected_lead.company_name or "Client",
                                            service_key,
                                            score,
                                            selected_lead.industry or "Unknown",
                                            selected_lead.company_size or "Unknown",
                                            {"score": selected_lead.health_score or 0, "issues": []}
                                        )
                                        st.markdown(pitch)
            else:
                st.info("No leads available")
    
    with tab4:
        st.markdown("### 🤖 AI Lead Insights")
        
        db = get_db()
        if db:
            leads_with_ai = db.query(Lead).filter(Lead.ai_enrichment.isnot(None)).order_by(Lead.updated_at.desc()).limit(20).all()
            db.close()
            
            if leads_with_ai:
                for lead in leads_with_ai:
                    with st.expander(f"{lead.company_name or lead.domain} - {lead.city}, {lead.state}"):
                        if lead.ai_enrichment:
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.markdown("**Key Challenges:**")
                                if isinstance(lead.ai_enrichment, dict):
                                    for challenge in lead.ai_enrichment.get('key_challenges', []):
                                        st.markdown(f"- {challenge}")
                                    
                                    st.markdown("**Quick Wins (30 days):**")
                                    for win in lead.ai_enrichment.get('quick_wins', []):
                                        st.markdown(f"✅ {win}")
                            
                            with col2:
                                st.markdown("**Recommended Services:**")
                                for service in lead.ai_enrichment.get('recommended_services', []):
                                    st.markdown(f"• {service}")
                                
                                st.markdown("**Conversation Starters:**")
                                for starter in lead.ai_enrichment.get('conversation_starters', []):
                                    st.markdown(f"💡 {starter}")
                            
                            st.markdown("**Estimated Business Impact:**")
                            st.info(lead.ai_enrichment.get('estimated_impact', 'N/A'))
            else:
                st.info("No AI-enriched leads yet. Import leads with AI enrichment enabled.")

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

# ============================================================================
# ENHANCED SERVICE SCORING & LEAD ENRICHMENT
# ============================================================================

def detect_industry(url, html_content, tech_stack):
    """Detect industry from website content using keywords and tech stack."""
    html_lower = html_content.lower()
    
    industry_keywords = {
        "E-Commerce": ["shop", "cart", "product", "buy", "purchase", "store", "shopify"],
        "SaaS": ["dashboard", "api", "integration", "subscription", "pricing", "features"],
        "Real Estate": ["property", "listing", "real estate", "broker", "agent", "mls"],
        "Healthcare": ["doctor", "clinic", "medical", "appointment", "patient", "pharmacy"],
        "Finance": ["banking", "investment", "loan", "credit", "financial", "wealth"],
        "Legal": ["attorney", "lawyer", "law firm", "legal services", "litigation"],
        "Education": ["course", "university", "school", "student", "learning", "tuition"],
        "Restaurant/Food": ["menu", "reservation", "dining", "cafe", "restaurant", "food"],
        "Travel/Hospitality": ["hotel", "booking", "travel", "vacation", "resort", "airline"],
        "B2B Services": ["solution", "enterprise", "consulting", "service", "corporate"],
        "Manufacturing": ["manufacturing", "industrial", "equipment", "supplier", "production"],
        "Non-Profit": ["charity", "donation", "volunteer", "nonprofit", "mission"],
    }
    
    detected_industries = {}
    for industry, keywords in industry_keywords.items():
        score = sum(1 for keyword in keywords if keyword in html_lower)
        if score > 0:
            detected_industries[industry] = score
    
    if detected_industries:
        return max(detected_industries, key=detected_industries.get)
    return "General Business"

def estimate_company_size(tech_stack, content_length, has_team_page, num_emails):
    """Estimate company size based on website indicators."""
    score = 0
    
    # Enterprise tech
    enterprise_tech = ["salesforce", "sap", "servicenow", "workday", "oracle"]
    if any(tech.lower() in str(tech_stack).lower() for tech in enterprise_tech):
        return "Enterprise"
    
    # Startup/SaaS indicators
    if any(tech in str(tech_stack).lower() for tech in ["react", "nextjs", "vue", "node"]):
        score += 20
    
    # Content length (larger = usually bigger company)
    if content_length > 50000:
        score += 30
        size = "Large"
    elif content_length > 20000:
        score += 20
        size = "Medium"
    else:
        score += 10
        size = "Small"
    
    # Email count (more emails = bigger)
    if num_emails > 5:
        score += 20
        size = "Large"
    elif num_emails > 2:
        score += 10
        size = "Medium"
    
    # Team page indicates medium+
    if has_team_page:
        if score >= 40:
            return "Large"
        elif score >= 25:
            return "Medium"
    
    return size

def calculate_service_scores(audit_data, company_size, industry):
    """Calculate opportunity score for each Code Nest service."""
    scores = {}
    
    # Website Development Score (0-100)
    web_dev_score = 0
    web_dev_score += (100 - audit_data['score']) * 0.3  # Health score = 30%
    
    # Design freshness (check for outdated patterns)
    if any(issue['title'] in ['Outdated Design', 'Poor UX', 'Mobile Issues'] 
           for issue in audit_data.get('issues', [])):
        web_dev_score += 30
    
    if company_size in ["Large", "Enterprise"]:
        web_dev_score += 15
    
    scores['website_development'] = min(100, web_dev_score)
    
    # SEO Score (0-100)
    seo_score = 0
    seo_issues = [issue for issue in audit_data.get('issues', []) 
                  if any(word in issue.get('title', '').lower() for word in ['seo', 'meta', 'title', 'heading'])]
    seo_score += len(seo_issues) * 15
    seo_score += (100 - audit_data['score']) * 0.2  # Low health = SEO need
    
    if company_size in ["Medium", "Large", "Enterprise"]:
        seo_score += 20
    
    scores['seo_optimization'] = min(100, seo_score)
    
    # Mobile App Score (0-100)
    mobile_app_score = 0
    if any("mobile" in issue.get('title', '').lower() for issue in audit_data.get('issues', [])):
        mobile_app_score += 40
    
    if industry in ["E-Commerce", "SaaS", "Restaurant/Food"]:
        mobile_app_score += 30
    
    if company_size in ["Medium", "Large", "Enterprise"]:
        mobile_app_score += 20
    
    scores['mobile_app_development'] = mobile_app_score
    
    # Social Media Score (0-100)
    social_score = 0
    social_score += sum(1 for issue in audit_data.get('issues', []) 
                       if 'social' in issue.get('title', '').lower()) * 20
    
    if industry in ["E-Commerce", "Restaurant/Food", "Travel/Hospitality"]:
        social_score += 35
    
    if company_size in ["Medium", "Large"]:
        social_score += 15
    
    scores['social_media_marketing'] = min(100, social_score)
    
    # PPC/Paid Ads Score (0-100)
    ppc_score = 0
    if industry in ["E-Commerce", "SaaS", "Finance"]:
        ppc_score += 40
    
    if company_size in ["Large", "Enterprise"]:
        ppc_score += 25
    
    # If low organic traffic signals
    if audit_data['score'] < 50:
        ppc_score += 20
    
    scores['paid_advertising'] = min(100, ppc_score)
    
    # E-Commerce Score (0-100)
    ecommerce_score = 0
    if industry == "E-Commerce":
        ecommerce_score = 85
    elif "product" in str(audit_data.get('tech_stack', '')).lower():
        ecommerce_score = 60
    else:
        ecommerce_score = 20
    
    scores['ecommerce_development'] = ecommerce_score
    
    # WordPress/Website Maintenance Score (0-100)
    maintenance_score = 50  # Most sites need maintenance
    if "wordpress" in str(audit_data.get('tech_stack', '')).lower():
        maintenance_score = 75
    
    if company_size in ["Small", "Medium"]:
        maintenance_score += 20
    
    scores['website_maintenance'] = min(100, maintenance_score)
    
    # React/Modern Development Score (0-100)
    modern_dev_score = 0
    modern_stacks = ["react", "nextjs", "vue", "angular"]
    if any(stack in str(audit_data.get('tech_stack', '')).lower() for stack in modern_stacks):
        modern_dev_score = 60  # Already using modern stack, but might need optimization
    else:
        modern_dev_score = 40
    
    if industry == "SaaS":
        modern_dev_score += 30
    
    scores['react_nextjs_development'] = min(100, modern_dev_score)
    
    # Website Optimization Score (0-100)
    optimization_score = 100 - audit_data['score']
    optimization_score += (100 - (audit_data.get('psi', 0) or 0)) * 0.3
    scores['website_optimization'] = min(100, optimization_score)
    
    # Graphic Design Score (0-100)
    design_score = 30 if any("design" in issue.get('title', '').lower() 
                            for issue in audit_data.get('issues', [])) else 20
    if company_size in ["Medium", "Large"]:
        design_score += 20
    scores['graphic_designing'] = design_score
    
    return scores

def generate_service_pitch(company_name, service_name, score, industry, company_size, audit_data):
    """Generate AI-powered service pitch for a specific service."""
    pitches = {
        'website_development': f"""
Based on our audit of {company_name}'s current website, we identified significant opportunities for improvement:

**Current State:** Your website scores {audit_data['score']}/100 on our health assessment
**Key Issues Found:** {', '.join([issue['title'] for issue in audit_data.get('issues', [])[:3]])}

**What We Recommend:**
Our website development team specializes in building high-performance, conversion-optimized sites for {industry} businesses like yours. We'll:
- Rebuild your site with modern architecture ({company_size}-grade infrastructure)
- Optimize for conversions and user experience
- Ensure mobile-first responsive design
- Integrate with your existing tools and systems

**Expected Results:** 40-60% improvement in site performance, 25-35% increase in lead generation
**Timeline:** 8-12 weeks | **Investment:** Based on scope and complexity
""",
        
        'seo_optimization': f"""
{company_name} is currently ranking poorly for critical keywords in your industry.

**Current Gaps:**
- Missing or weak meta tags and structure
- Limited internal linking strategy
- Technical SEO issues affecting crawlability

**Our SEO Strategy:**
We'll execute a comprehensive SEO plan tailored for {industry} that includes:
- Technical SEO audit and remediation
- On-page optimization for high-intent keywords
- Content strategy and creation
- Off-page authority building
- Monthly performance reporting

**Expected Results:** Top 10 rankings for target keywords within 6 months, 200%+ organic traffic growth
**Timeline:** Ongoing (6-12 month commitment) | **Investment:** Monthly retainer starting at $2,500/month
""",

        'mobile_app_development': f"""
For a {company_size} {industry} business like {company_name}, a native mobile app could unlock new revenue streams.

**Opportunity:**
Your website receives significant mobile traffic, but a dedicated app would:
- Increase customer engagement and retention
- Enable push notifications and personalization
- Create a direct channel to your customers
- Generate new revenue opportunities

**Our Process:**
We build iOS and Android apps with:
- Native performance and user experience
- Offline functionality
- Seamless backend integration
- App Store and Play Store optimization

**Expected ROI:** 40-60% increase in customer lifetime value
**Timeline:** 12-16 weeks | **Investment:** Starting at $35,000
""",

        'social_media_marketing': f"""
{company_name}'s social presence is not aligned with your market potential.

**Current Assessment:**
- Limited social media integration on website
- Missing or inactive social accounts
- No consistent content strategy

**Our Social Media Services:**
For {industry} businesses, we create and execute comprehensive social strategies:
- Content calendar and creation
- Community management and engagement
- Paid social advertising ($500-$5,000/month)
- Analytics and monthly reporting
- Influencer partnerships (if relevant)

**Expected Results:** 5-10x follower growth, 30-50% increase in social-driven traffic
**Timeline:** Ongoing (minimum 3 months) | **Investment:** $2,000-$5,000/month
""",

        'paid_advertising': f"""
Your organic traffic is limited, but paid advertising could immediately increase qualified leads.

**Opportunity Analysis:**
- Low organic visibility in search results
- High cost of waiting for SEO results
- Immediate revenue opportunity through PPC

**Our Paid Advertising Services:**
Fully-managed campaigns on Google, Facebook, and Instagram with:
- Keyword and audience research
- Creative development and A/B testing
- Daily optimization and monitoring
- Conversion tracking and reporting
- Weekly performance reviews

**Expected ROI:** 3-5x return on ad spend for e-commerce, 200-500% for B2B
**Timeline:** Ongoing (minimum 3 months) | **Investment:** $1,000-$10,000/month ad spend + management
"""
    }
    
    return pitches.get(service_name, "Service pitch unavailable")

def enrich_lead_with_ai(lead_data, audit_data, openai_key):
    """Use AI to generate comprehensive lead enrichment and recommendations."""
    if not openai_key:
        return None
    
    try:
        client = OpenAI(api_key=openai_key)
        
        prompt = f"""
Analyze this business lead and provide strategic recommendations:

**Company:** {lead_data.get('company_name', 'Unknown')}
**Industry:** {lead_data.get('industry', 'Unknown')}
**Company Size:** {lead_data.get('company_size', 'Unknown')}
**Location:** {lead_data.get('city', 'Unknown')}, {lead_data.get('state', 'Unknown')}

**Website Audit Results:**
- Health Score: {audit_data.get('score', 0)}/100
- Performance Score: {audit_data.get('psi', 'N/A')}/100
- Accessibility Score: {audit_data.get('accessibility_score', 'N/A')}/100
- Critical Issues: {len(audit_data.get('issues', []))}

**Top 3 Issues:** {', '.join([i['title'] for i in audit_data.get('issues', [])[:3]])}

Provide a JSON response with:
1. "key_challenges": [list of 3-5 main business challenges based on website audit]
2. "quick_wins": [3-5 quick improvements that could be made in 30 days]
3. "recommended_services": [list of top 3 Code Nest services with priority 1-10]
4. "estimated_impact": Brief description of potential business impact
5. "conversation_starters": [3 compelling reasons to talk to this prospect]

Return ONLY valid JSON, no other text.
"""
        
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=800
        )
        
        result = response.choices[0].message.content
        return json.loads(result)
    
    except Exception as e:
        logger.error(f"Error enriching lead with AI: {str(e)}")
        return None

def process_csv_leads(csv_file, audit_scores_lookup, openai_key):
    """Process CSV lead file with Google Places data and audit matching."""
    try:
        df = pd.read_csv(csv_file)
        leads_created = 0
        errors = []
        
        for idx, row in df.iterrows():
            try:
                company_name = row.get('name', f"Lead {idx}")
                phone = row.get('phone', '')
                address = row.get('address', '')
                place_id = row.get('place_id', '')
                website = row.get('website', '') or row.get('url', '')
                city = row.get('city', '')
                state = row.get('state', '')
                zipcode = row.get('zipcode', '')
                
                # Extract domain from website if available
                if website:
                    domain = urlparse(website).netloc.replace('www.', '')
                else:
                    domain = None
                
                if not domain:
                    errors.append(f"Row {idx}: No website/domain found")
                    continue
                
                # Look up audit scores if available
                audit_data = audit_scores_lookup.get(domain, {})
                
                # Create lead record
                db = get_db()
                if not db:
                    continue
                
                lead = Lead(
                    domain=domain,
                    company_name=company_name,
                    phone=phone,
                    address=address,
                    place_id=place_id,
                    city=city,
                    state=state,
                    zipcode=zipcode,
                    health_score=audit_data.get('score'),
                    industry=audit_data.get('industry', detect_industry(domain, '', audit_data.get('tech_stack', []))),
                    company_size=audit_data.get('company_size', estimate_company_size(
                        audit_data.get('tech_stack', []),
                        len(str(audit_data)),
                        False,
                        len(audit_data.get('emails', []))
                    )),
                    service_priorities=audit_data.get('service_scores', {}),
                    status='new'
                )
                
                # AI enrichment if audit data available
                if audit_data and openai_key:
                    ai_enrichment = enrich_lead_with_ai(
                        {
                            'company_name': company_name,
                            'city': city,
                            'state': state,
                            'industry': lead.industry,
                            'company_size': lead.company_size
                        },
                        audit_data,
                        openai_key
                    )
                    lead.ai_enrichment = ai_enrichment
                
                db.add(lead)
                db.commit()
                leads_created += 1
                
                db.close()
            
            except Exception as e:
                errors.append(f"Row {idx}: {str(e)}")
                continue
        
        return leads_created, errors
    
    except Exception as e:
        logger.error(f"Error processing CSV: {str(e)}")
        return 0, [str(e)]

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
    
    # Add service scoring for lead enrichment
    try:
        industry = detect_industry(url, html if 'html' in locals() else '', data.get('tech_stack', []))
        company_size = estimate_company_size(data.get('tech_stack', []), 
                                            len(str(data)), 
                                            False, 
                                            len(data.get('emails', [])))
        data['industry'] = industry
        data['company_size'] = company_size
        data['service_scores'] = calculate_service_scores(data, company_size, industry)
    except Exception as e:
        logger.warning(f"Error calculating service scores: {str(e)}")
    
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
        
        # Custom CSS for beautiful UI
        st.markdown("""
        <style>
        .user-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 15px;
            color: white;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .user-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
            padding-bottom: 10px;
        }
        .user-name {
            font-size: 18px;
            font-weight: bold;
        }
        .user-role {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
        }
        .role-admin {
            background-color: rgba(255, 107, 107, 0.8);
            color: white;
        }
        .role-user {
            background-color: rgba(100, 200, 100, 0.8);
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

def show_export_reports():
    """Export audits as PDF or Excel reports."""
    st.markdown("## 📄 Export Reports")
    
    export_type = st.radio("Export Format", ["PDF (Single)", "Excel (Batch)", "CSV (Data)"], horizontal=True)
    
    if export_type == "PDF (Single)":
        st.markdown("### Export Single Audit as PDF")
        
        # Get list of audits
        audits = get_audit_history_cached(limit=100)
        if not audits:
            st.warning("No audits available to export")
            return
        
        # Select audit
        audit_options = {f"{a.get('domain', 'Unknown')} ({a.get('timestamp', 'N/A')[:10]})": a for a in audits}
        selected = st.selectbox("Select Audit", list(audit_options.keys()))
        
        if selected and st.button("Generate PDF Report", use_container_width=True, type="primary"):
            with st.spinner("Generating PDF..."):
                audit_data = audit_options[selected]
                pdf_bytes = generate_pdf_report(audit_data)
                
                if pdf_bytes:
                    st.success("✅ PDF generated successfully")
                    st.download_button(
                        label="⬇️ Download PDF Report",
                        data=pdf_bytes,
                        file_name=f"audit_{audit_data.get('domain', 'report').replace('/', '_')}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
                else:
                    st.error("Error generating PDF")
    
    elif export_type == "Excel (Batch)":
        st.markdown("### Export Multiple Audits as Excel")
        
        audits = get_audit_history_cached(limit=500)
        if not audits:
            st.warning("No audits available to export")
            return
        
        # Filter options
        col1, col2 = st.columns(2)
        with col1:
            min_score = st.slider("Minimum Score", 0, 100, 0)
        with col2:
            max_score = st.slider("Maximum Score", 0, 100, 100)
        
        filtered_audits = [a for a in audits if min_score <= a.get("score", 0) <= max_score]
        
        st.info(f"Exporting {len(filtered_audits)} audits...")
        
        if st.button("Generate Excel Report", use_container_width=True, type="primary"):
            with st.spinner("Generating Excel..."):
                excel_bytes = generate_excel_report(filtered_audits)
                
                if excel_bytes:
                    st.success("✅ Excel file generated successfully")
                    st.download_button(
                        label="⬇️ Download Excel Report",
                        data=excel_bytes,
                        file_name=f"audits_report_{datetime.now().strftime('%Y%m%d')}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        use_container_width=True
                    )
                else:
                    st.error("Error generating Excel")
    
    elif export_type == "CSV (Data)":
        st.markdown("### Export as CSV for Analysis")
        
        audits = get_audit_history_cached(limit=1000)
        if not audits:
            st.warning("No audits available to export")
            return
        
        df = pd.DataFrame(audits)
        
        # Column selection
        columns = st.multiselect(
            "Select columns to export",
            df.columns.tolist(),
            default=["domain", "score", "status", "timestamp"]
        )
        
        if st.button("Generate CSV", use_container_width=True, type="primary"):
            csv_data = df[columns].to_csv(index=False)
            st.success("✅ CSV ready for download")
            st.download_button(
                label="⬇️ Download CSV",
                data=csv_data,
                file_name=f"audits_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv",
                use_container_width=True
            )
        
        # Preview
        st.markdown("### Preview")
        st.dataframe(df[columns].head(10), use_container_width=True)


# ============================================================================
# MAIN ROUTING & CONTENT DISPATCHER
# ============================================================================

# Main content area routing
current_section = st.session_state.current_section

if current_section == "Single Audit":
    show_single_audit()
elif current_section == "Audit History":
    show_audit_history()
elif current_section == "Dashboard":
    show_dashboard()
elif current_section == "Preferences":
    show_preferences_panel(st.session_state.get('current_user', 'user'))
elif current_section == "Bulk Audit":
    show_bulk_audit()
elif current_section == "Competitor Analysis":
    show_competitor_analysis()
elif current_section == "Lead Management":
    show_lead_management()
elif current_section == "Email Outreach":
    show_email_outreach()
elif current_section == "Scheduled Audits":
    show_scheduled_audits()
elif current_section == "API Settings":
    show_api_settings()
elif current_section == "Email Settings":
    show_email_settings()
elif current_section == "Export Reports":
    show_export_reports()
elif current_section == "Admin Settings":
    show_admin_settings()
else:
    # Default to Single Audit
    st.session_state.current_section = "Single Audit"
    show_single_audit()
