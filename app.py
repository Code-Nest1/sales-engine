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

# Load environment variables from a local .env file if present
load_dotenv()
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from models import init_db, get_db, Audit, Lead, EmailOutreach, DATABASE_URL, User
from passlib.hash import bcrypt

# Initialize database and check connectivity
DB_AVAILABLE = False
if DATABASE_URL:
    try:
        DB_AVAILABLE = init_db()
    except Exception as e:
        DB_AVAILABLE = False

# --- CONFIGURATION ---
st.set_page_config(page_title="Code Nest Sales Engine", layout="wide", page_icon="🦅")

# --- BRANDING ---
COMPANY_NAME = "Code Nest"
COMPANY_TAGLINE = "Launch. Scale. Optimize."
CONTACT_EMAIL = "services@codenest.agency"

# --- SIDEBAR CONFIG ---
with st.sidebar:
    st.header("🦅 Engine Settings")
    st.caption("Configure your intelligence sources.")
    
    # Check for OPENAI_API_KEY in environment first, then allow manual input
    env_openai_key = os.environ.get("OPENAI_API_KEY")
    if env_openai_key:
        st.success("OpenAI API Key: Connected")
        OPENAI_API_KEY = env_openai_key
    else:
        openai_input = st.text_input("OpenAI API Key (Required for Pitch)", type="password")
        OPENAI_API_KEY = openai_input.strip() if openai_input else None
    
    google_input = st.text_input("Google PageSpeed Key (Optional)", type="password")
    GOOGLE_API_KEY = google_input.strip() if google_input else None
    
    st.divider()
    if DB_AVAILABLE:
        st.info("System Status: **Active**\n\nDatabase: Connected\n\nPlatform: Replit Cloud")
    else:
        st.warning("System Status: **Limited**\n\nDatabase: Not Connected\n\nSome features require database.")

    # --- Authentication ---
    if 'user_id' not in st.session_state:
        st.session_state['user_id'] = None
        st.session_state['username'] = None
        st.session_state['is_authenticated'] = False

    def hash_password(password: str) -> str:
        return bcrypt.hash(password)

    def verify_password(password: str, hashed: str) -> bool:
        try:
            return bcrypt.verify(password, hashed)
        except Exception:
            return False

    def get_user_by_username(username: str):
        db = get_db()
        if not db:
            return None
        try:
            return db.query(User).filter(User.username == username).first()
        finally:
            db.close()

    def create_user(username: str, email: str, password: str):
        db = get_db()
        if not db:
            return None
        try:
            existing = db.query(User).filter((User.username==username)|(User.email==email)).first()
            if existing:
                return None
            user = User(username=username, email=email, password_hash=hash_password(password))
            db.add(user)
            db.commit()
            db.refresh(user)
            return user
        finally:
            db.close()

    def authenticate_user(username: str, password: str):
        user = get_user_by_username(username)
        if not user:
            return None
        if verify_password(password, user.password_hash):
            return user
        return None

    # Show login/register depending on authentication state
    if not st.session_state.get('is_authenticated'):
        auth_tab = st.selectbox("Account", ["Login", "Register"], key="auth_mode")
        if auth_tab == "Login":
            with st.form(key="login_form"):
                login_user = st.text_input("Username")
                login_pass = st.text_input("Password", type="password")
                submit_login = st.form_submit_button("Login")
                if submit_login:
                    user = authenticate_user(login_user, login_pass)
                    if user:
                        st.session_state['user_id'] = user.id
                        st.session_state['username'] = user.username
                        st.session_state['is_authenticated'] = True
                        st.success(f"Welcome back, {user.username}!")
                        st.experimental_rerun()
                    else:
                        st.error("Invalid username or password.")
        else:
            with st.form(key="register_form"):
                reg_user = st.text_input("Choose a username")
                reg_email = st.text_input("Email (optional)")
                reg_pass = st.text_input("Choose a password", type="password")
                reg_pass2 = st.text_input("Confirm password", type="password")
                submit_reg = st.form_submit_button("Register")
                if submit_reg:
                    if not reg_user or not reg_pass:
                        st.warning("Please choose a username and password.")
                    elif reg_pass != reg_pass2:
                        st.warning("Passwords do not match.")
                    else:
                        new_user = create_user(reg_user, reg_email or None, reg_pass)
                        if new_user:
                            st.success("Account created. You may now log in.")
                        else:
                            st.error("User already exists or registration failed.")
    else:
        st.markdown(f"**Signed in as:** {st.session_state.get('username')} ")
        if st.button("Logout"):
            st.session_state['user_id'] = None
            st.session_state['username'] = None
            st.session_state['is_authenticated'] = False
            st.experimental_rerun()

# --- HELPER FUNCTIONS ---

def clean_text(text):
    """Sanitizes text for PDF generation."""
    if not text: return ""
    text = text.replace('\u201c', '"').replace('\u201d', '"').replace('\u2019', "'").replace('\u2013', '-')
    return text.encode('latin-1', 'replace').decode('latin-1')

def get_domain_age(url):
    """Determines business maturity via domain age."""
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
    except Exception as e:
        return "Unknown (Privacy Protected)", 0
    return "Unknown", 0

def get_google_speed(url, api_key):
    """Fetches Core Web Vitals from Google PSI."""
    if not api_key: return None, "No API Key"
    
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
            return None, f"Google Error: {r.status_code}"
    except Exception as e:
        return None, str(e)

# --- AI BRAIN ---
# the newest OpenAI model is "gpt-5" which was released August 7, 2025.
# do not change this unless explicitly requested by the user

def get_ai_consultation(url, data, api_key):
    """Uses GPT-5 to act as a Senior Consultant."""
    if not api_key:
        return {
            "summary": "AI Analysis Disabled (No Key).",
            "impact": "Unknown.",
            "solutions": "Standard Web Dev Services.",
            "email": "Please add OpenAI Key to generate email."
        }

    issues_list = [f"- {i['title']}: {i['impact']}" for i in data['issues']]
    tech_list = ", ".join(data['tech_stack'])
    
    prompt = f"""
    You are a Senior Digital Strategist at Code Nest (Agency). Analyze this website: {url}.
    
    DATA DETECTED:
    Tech Stack: {tech_list}
    Issues Found:
    {chr(10).join(issues_list)}
    
    TASK 1: Write an Executive Summary (2 sentences max).
    TASK 2: Summarize Business Impact (Financial/Brand loss).
    TASK 3: List 3 specific Code Nest services to fix these.
    TASK 4: Write a Cold Email to the owner. Tone: Professional, Expert.
    
    Output format: Return the 4 sections separated by '###'.
    """

    try:
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model="gpt-5",
            messages=[{"role": "user", "content": prompt}]
        )
        content = response.choices[0].message.content
        parts = content.split("###")
        
        return {
            "summary": parts[1] if len(parts) > 1 else "Analysis generated.",
            "impact": parts[2] if len(parts) > 2 else "Potential revenue loss detected.",
            "solutions": parts[3] if len(parts) > 3 else "Optimization.",
            "email": parts[4] if len(parts) > 4 else "Contact us."
        }
    except Exception as e:
        return {"summary": "Error", "impact": "Error", "solutions": "Error", "email": str(e)}

# --- MAIN AUDIT LOGIC ---

def run_audit(url, openai_key, google_key):
    if not url.startswith('http'): url = 'http://' + url
    
    data = {
        "url": url,
        "score": 100,
        "issues": [],
        "tech_stack": [],
        "emails": [],
        "psi": None,
        "psi_error": None,
        "domain_age": "Unknown"
    }

    try:
        # 1. CONNECTIVITY
        start = time.time()
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=30)
        load_time = time.time() - start
        
        html = response.text.lower()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 2. BASIC INFO
        data['domain_age'] = get_domain_age(url)[0]
        data['emails'] = list(set(re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", html)))

        # 3. TECH DETECTION
        if "wp-content" in html: 
            data['tech_stack'].append("WordPress")
            data['score'] -= 10
            data['issues'].append({"title": "WordPress Detected", "impact": "Requires monthly security maintenance.", "solution": "Code Nest Maintenance Plan"})
        elif "shopify" in html: 
            data['tech_stack'].append("Shopify")
        elif "wix" in html:
            data['tech_stack'].append("Wix")
        elif "squarespace" in html:
            data['tech_stack'].append("Squarespace")
        elif "webflow" in html:
            data['tech_stack'].append("Webflow")
        
        # 4. MARKETING
        pixels = []
        if "fbq(" in html: pixels.append("Facebook Pixel")
        if "gtag(" in html or "ua-" in html or "g-" in html: pixels.append("Google Analytics")
        if "linkedin" in html and "insight" in html: pixels.append("LinkedIn Insight")
        if "hotjar" in html: pixels.append("Hotjar")
        
        if not pixels:
            data['score'] -= 20
            data['issues'].append({"title": "Zero Tracking Installed", "impact": "You are flying blind. No data on customer behavior.", "solution": "Analytics Setup"})
        else:
            data['tech_stack'].extend(pixels)

        # 5. SEO BASICS
        title = soup.title.string if soup.title else ""
        if len(title) < 10:
            data['score'] -= 10
            data['issues'].append({"title": "Weak Title Tag", "impact": "Google ignores pages with poor titles.", "solution": "On-Page SEO"})
        
        # Check meta description
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if not meta_desc or not meta_desc.get('content'):
            data['score'] -= 10
            data['issues'].append({"title": "Missing Meta Description", "impact": "Search engines won't show a compelling snippet.", "solution": "SEO Optimization"})
        
        # Check for SSL
        if not url.startswith('https'):
            data['score'] -= 15
            data['issues'].append({"title": "No SSL Certificate", "impact": "Browser shows 'Not Secure' warning. Customers lose trust.", "solution": "SSL Installation"})

        # 6. PERFORMANCE (PSI)
        psi_score, psi_msg = get_google_speed(url, google_key)
        if psi_score:
            data['psi'] = psi_score
            if psi_score < 50:
                data['score'] -= 20
                data['issues'].append({"title": f"Critical Speed Score ({psi_score}/100)", "impact": "Users abandon slow sites.", "solution": "Core Web Vitals Optimization"})
        else:
            data['psi_error'] = psi_msg
            if load_time > 3.0:
                data['score'] -= 10
                data['issues'].append({"title": "Slow Server Response", "impact": f"Load time {round(load_time,2)}s is too slow.", "solution": "Speed Optimization"})

        # 7. Mobile responsiveness check
        viewport = soup.find('meta', attrs={'name': 'viewport'})
        if not viewport:
            data['score'] -= 10
            data['issues'].append({"title": "Not Mobile Optimized", "impact": "60% of traffic is mobile. You're losing customers.", "solution": "Responsive Design"})

        # 8. AI CONSULTATION
        data['ai'] = get_ai_consultation(url, data, openai_key)

    except Exception as e:
        data['error'] = str(e)

    # Ensure score doesn't go below 0
    data['score'] = max(0, data['score'])

    return data

# --- PDF GENERATOR ---

class PDFReport(FPDF):
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
    pdf = PDFReport()
    pdf.add_page()

    # COVER
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, f"Website Audit: {clean_text(data['url'])}", 0, 1)
    
    if data['score'] > 70:
        pdf.set_text_color(0, 128, 0)
    elif data['score'] > 40:
        pdf.set_text_color(255, 165, 0)
    else:
        pdf.set_text_color(200, 0, 0)
    pdf.cell(0, 10, f"Health Score: {data['score']}/100", 0, 1)
    
    pdf.set_text_color(0, 0, 0)
    pdf.set_font('Arial', '', 10)
    pdf.cell(0, 6, f"Domain Age: {data.get('domain_age', 'Unknown')}", 0, 1)
    pdf.cell(0, 6, f"Report Generated: {datetime.now().strftime('%B %d, %Y')}", 0, 1)
    if data['emails']:
        pdf.cell(0, 6, f"Contacts: {', '.join(data['emails'][:3])}", 0, 1)
    pdf.ln(5)

    # EXECUTIVE SUMMARY
    if data.get('ai'):
        pdf.section_title("1. Executive Strategy Summary")
        pdf.set_font('Arial', 'I', 10)
        pdf.multi_cell(0, 6, clean_text(data['ai'].get('summary', '').strip()))
        pdf.ln(2)

    # TECH STACK
    pdf.section_title("2. Technology & Infrastructure")
    tech = ", ".join(data['tech_stack']) if data['tech_stack'] else "Standard HTML"
    pdf.chapter_body(f"Detected Stack: {tech}")

    # ISSUES
    pdf.section_title("3. Critical Findings")
    if data['issues']:
        for issue in data['issues']:
            pdf.set_font('Arial', 'B', 10)
            pdf.set_text_color(180, 0, 0)
            pdf.cell(0, 6, f"[!] {clean_text(issue['title'])}", 0, 1)
            pdf.set_font('Arial', '', 10)
            pdf.set_text_color(50, 50, 50)
            pdf.multi_cell(0, 5, f"Impact: {clean_text(issue['impact'])}")
            pdf.set_text_color(0, 102, 51)
            pdf.multi_cell(0, 5, f"Solution: {clean_text(issue['solution'])}")
            pdf.ln(3)
    else:
        pdf.chapter_body("No critical issues detected. Website is performing well.")

    # AI EMAIL
    if data.get('ai'):
        pdf.section_title("4. Recommended Outreach Email")
        pdf.set_font('Courier', '', 10)
        pdf.set_text_color(0,0,0)
        pdf.multi_cell(0, 5, clean_text(data['ai'].get('email', '').strip()))

    # FOOTER
    pdf.ln(10)
    pdf.set_font('Arial', 'I', 9)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, f"Report by {COMPANY_NAME} | {CONTACT_EMAIL}", 0, 1, 'C')

    return pdf.output(dest='S').encode('latin-1')

# --- DATABASE FUNCTIONS ---

def save_audit_to_db(data, comparison_group=None):
    """Saves audit results to database."""
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
        
        # Also create/update lead
        existing_lead = db.query(Lead).filter(Lead.domain == domain).first()
        if not existing_lead:
            lead = Lead(
                domain=domain,
                email=data['emails'][0] if data.get('emails') else None,
                health_score=data['score'],
                opportunity_rating=calculate_opportunity_score(data)
            )
            db.add(lead)
            db.commit()
        else:
            existing_lead.health_score = data['score']
            existing_lead.opportunity_rating = calculate_opportunity_score(data)
            existing_lead.updated_at = datetime.utcnow()
            db.commit()
        
        return audit.id
    except Exception as e:
        db.rollback()
        return None
    finally:
        db.close()

def calculate_opportunity_score(data):
    """Calculate opportunity score for a lead."""
    opp_score = 0
    if data['score'] < 50: opp_score += 5
    if data['score'] < 30: opp_score += 3
    if not any("Pixel" in t for t in data.get('tech_stack', [])): opp_score += 3
    if not any("Analytics" in t for t in data.get('tech_stack', [])): opp_score += 2
    if len(data.get('issues', [])) > 3: opp_score += 2
    return opp_score

def get_audit_history(limit=50, search_query=None, min_score=None, max_score=None):
    """Retrieve audit history from database."""
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
    except Exception as e:
        return []
    finally:
        db.close()

def get_leads(status_filter=None):
    """Retrieve leads from database."""
    db = get_db()
    if not db:
        return []
    
    try:
        query = db.query(Lead).order_by(Lead.opportunity_rating.desc())
        if status_filter and status_filter != "all":
            query = query.filter(Lead.status == status_filter)
        return query.all()
    except Exception as e:
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
    except Exception as e:
        db.rollback()
        return False
    finally:
        db.close()

def save_email_outreach(recipient_email, subject, body, lead_id=None):
    """Save email outreach record."""
    db = get_db()
    if not db:
        return None
    
    try:
        outreach = EmailOutreach(
            lead_id=lead_id,
            recipient_email=recipient_email,
            subject=subject,
            body=body,
            status="draft"
        )
        db.add(outreach)
        db.commit()
        db.refresh(outreach)
        return outreach.id
    except Exception as e:
        db.rollback()
        return None
    finally:
        db.close()

def mark_email_sent(email_id):
    """Mark email as sent."""
    db = get_db()
    if not db:
        return False
    
    try:
        outreach = db.query(EmailOutreach).filter(EmailOutreach.id == email_id).first()
        if outreach:
            outreach.status = "sent"
            outreach.sent_at = datetime.utcnow()
            db.commit()
            return True
        return False
    except Exception as e:
        db.rollback()
        return False
    finally:
        db.close()

def get_scheduled_audits():
    """Get audits that are scheduled for re-run."""
    db = get_db()
    if not db:
        return []
    
    try:
        return db.query(Audit).filter(Audit.is_scheduled == True).order_by(Audit.next_scheduled_run).all()
    except Exception as e:
        return []
    finally:
        db.close()

def schedule_audit(audit_id, interval_days):
    """Schedule an audit for re-running."""
    db = get_db()
    if not db:
        return False
    
    try:
        audit = db.query(Audit).filter(Audit.id == audit_id).first()
        if audit:
            audit.is_scheduled = True
            audit.schedule_interval_days = interval_days
            audit.next_scheduled_run = datetime.utcnow() + timedelta(days=interval_days)
            db.commit()
            return True
        return False
    except Exception as e:
        db.rollback()
        return False
    finally:
        db.close()

def run_scheduled_audit(audit_id, openai_key, google_key):
    """Run a scheduled audit and update timestamps."""
    db = get_db()
    if not db:
        return None, None
    
    try:
        audit = db.query(Audit).filter(Audit.id == audit_id).first()
        if not audit:
            db.close()
            return None, None
        
        url = audit.url
        old_score = audit.health_score
        interval = audit.schedule_interval_days or 30
        db.close()
        
        new_data = run_audit(url, openai_key, google_key)
        new_audit_id = save_audit_to_db(new_data)
        
        if not new_audit_id:
            return new_data, old_score
        
        db = get_db()
        if db:
            try:
                new_audit = db.query(Audit).filter(Audit.id == new_audit_id).first()
                if new_audit:
                    new_audit.is_scheduled = True
                    new_audit.schedule_interval_days = interval
                    new_audit.last_scheduled_run = datetime.utcnow()
                    new_audit.next_scheduled_run = datetime.utcnow() + timedelta(days=interval)
                    db.commit()
                    
                    old_audit = db.query(Audit).filter(Audit.id == audit_id).first()
                    if old_audit:
                        old_audit.is_scheduled = False
                        db.commit()
            finally:
                db.close()
        
        return new_data, old_score
    except Exception as e:
        return None, None

# --- UI LAYER ---

st.title("🦅 Code Nest Sales Engine")
st.caption("Intelligent Website Auditing & Lead Generation Platform")

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🚀 Single Audit", 
    "📂 Bulk Processor", 
    "📊 Audit History",
    "🔄 Competitor Analysis",
    "📧 Email Outreach",
    "⏰ Scheduled Audits"
])

with tab1:
    st.markdown("### Run a Deep Diagnostic")
    st.markdown("Enter a website URL to analyze its technical health, SEO, performance, and generate an AI-powered sales pitch.")
    
    url = st.text_input("Website URL", placeholder="example.com")
    
    if st.button("Analyze Website", type="primary"):
        if not url:
            st.warning("Please enter a URL.")
        else:
            with st.spinner("Analyzing website... This may take a moment."):
                data = run_audit(url, OPENAI_API_KEY, GOOGLE_API_KEY)
                
                if "error" in data and not data['issues']:
                    st.error(f"Scan Failed: {data['error']}")
                else:
                    # Metrics Dashboard
                    st.markdown("---")
                    c1, c2, c3, c4 = st.columns(4)
                    
                    # Color-coded health score
                    if data['score'] > 70:
                        c1.metric("Health Score", f"{data['score']}/100", delta="Good")
                    elif data['score'] > 40:
                        c1.metric("Health Score", f"{data['score']}/100", delta="Needs Work", delta_color="off")
                    else:
                        c1.metric("Health Score", f"{data['score']}/100", delta="Critical", delta_color="inverse")
                    
                    c2.metric("Google Speed", data['psi'] if data['psi'] else "N/A")
                    c3.metric("Issues Found", len(data['issues']))
                    c4.metric("Domain Age", data.get('domain_age', 'Unknown'))
                    
                    # Tech Stack
                    if data['tech_stack']:
                        st.markdown("**Detected Technologies:** " + ", ".join(data['tech_stack']))
                    
                    # Contact Emails
                    if data['emails']:
                        st.markdown("**Contact Emails Found:** " + ", ".join(data['emails'][:5]))
                    
                    # Issues Breakdown
                    if data['issues']:
                        st.markdown("---")
                        st.subheader("🔍 Issues Detected")
                        for issue in data['issues']:
                            with st.expander(f"⚠️ {issue['title']}"):
                                st.markdown(f"**Impact:** {issue['impact']}")
                                st.markdown(f"**Recommended Solution:** {issue['solution']}")
                    
                    # AI Analysis
                    if data.get('ai') and OPENAI_API_KEY:
                        st.markdown("---")
                        st.subheader("🤖 AI Analysis")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown("**Executive Summary**")
                            st.info(data['ai']['summary'])
                            
                            st.markdown("**Business Impact**")
                            st.warning(data['ai']['impact'])
                        
                        with col2:
                            st.markdown("**Recommended Solutions**")
                            st.success(data['ai']['solutions'])
                        
                        st.markdown("---")
                        st.markdown("**📧 Generated Cold Email**")
                        st.text_area("Cold Email Draft", value=clean_text(data['ai']['email']), height=250)
                    
                    # Save to database
                    audit_id = save_audit_to_db(data)
                    if audit_id:
                        st.success(f"Audit saved to history (ID: {audit_id})")
                    
                    # PDF Download
                    st.markdown("---")
                    try:
                        pdf_bytes = generate_pdf(data)
                        domain_name = urlparse(data['url']).netloc.replace("www.", "").replace(".", "_")
                        st.download_button(
                            "📥 Download PDF Report", 
                            pdf_bytes, 
                            f"CodeNest_Audit_{domain_name}.pdf", 
                            "application/pdf", 
                            type="primary"
                        )
                    except Exception as e:
                        st.error(f"PDF Generation Error: {e}")

with tab2:
    st.markdown("### Bulk Lead Qualifier")
    st.markdown("Upload a CSV file with a **'Website'** column to analyze multiple websites at once.")
    
    uploaded = st.file_uploader("Upload CSV", type="csv")
    
    if uploaded:
        df = pd.read_csv(uploaded)
        st.markdown(f"**Loaded {len(df)} rows**")
        
        if "Website" not in df.columns:
            st.error("CSV must have a 'Website' column.")
        else:
            st.dataframe(df.head())
            
            if st.button("Process Batch", type="primary"):
                results = []
                progress = st.progress(0)
                status = st.empty()
                
                for i, row_site in enumerate(df['Website']):
                    status.text(f"Analyzing {i+1}/{len(df)}: {row_site}")
                    d = run_audit(str(row_site).strip(), OPENAI_API_KEY, GOOGLE_API_KEY)
                    
                    # Save to database
                    save_audit_to_db(d)
                    
                    # Calculate opportunity score
                    opp_score = calculate_opportunity_score(d)
                    
                    results.append({
                        "Website": row_site,
                        "Health Score": d['score'],
                        "Google Speed": d['psi'] if d['psi'] else "N/A",
                        "Issues": len(d['issues']),
                        "Opportunity Rating": opp_score,
                        "Tech Stack": ", ".join(d['tech_stack']) if d['tech_stack'] else "Standard",
                        "Emails": ", ".join(d['emails'][:3]) if d['emails'] else "None"
                    })
                    progress.progress((i+1)/len(df))
                
                status.empty()
                st.success(f"Processed {len(df)} websites!")
                
                res_df = pd.DataFrame(results)
                
                # Sort by opportunity rating (highest first)
                res_df = res_df.sort_values(by="Opportunity Rating", ascending=False)
                
                st.dataframe(res_df, use_container_width=True)
                
                # Download results
                csv = res_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    "📥 Download Leads CSV", 
                    csv, 
                    "CodeNest_Qualified_Leads.csv", 
                    "text/csv",
                    type="primary"
                )

# --- TAB 3: AUDIT HISTORY ---
with tab3:
    st.markdown("### Audit History")
    st.markdown("View and search through all past website audits.")
    
    if not DB_AVAILABLE:
        st.error("Database connection required. Please ensure DATABASE_URL is configured to use this feature.")
        st.stop()

    # Filters
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        search_query = st.text_input("Search by domain", placeholder="example.com", key="history_search")
    with col2:
        min_score = st.number_input("Min Score", min_value=0, max_value=100, value=0, key="min_score")
    with col3:
        max_score = st.number_input("Max Score", min_value=0, max_value=100, value=100, key="max_score")

    # Get filtered history
    audits = get_audit_history(
        limit=100,
        search_query=search_query if search_query else None,
        min_score=min_score if min_score > 0 else None,
        max_score=max_score if max_score < 100 else None
    )
    
    if audits:
        # Convert to dataframe for display
        history_data = []
        for audit in audits:
            history_data.append({
                "ID": audit.id,
                "Domain": audit.domain,
                "URL": audit.url,
                "Health Score": audit.health_score,
                "PSI Score": audit.psi_score if audit.psi_score else "N/A",
                "Domain Age": audit.domain_age or "Unknown",
                "Issues": len(audit.issues) if audit.issues else 0,
                "Date": audit.created_at.strftime("%Y-%m-%d %H:%M") if audit.created_at else "N/A"
            })
        
        history_df = pd.DataFrame(history_data)
        st.dataframe(history_df, use_container_width=True)
        
        # Export option
        csv = history_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            "📥 Export History CSV",
            csv,
            "CodeNest_Audit_History.csv",
            "text/csv"
        )
        
        # Detail view
        st.markdown("---")
        st.markdown("### View Audit Details")
        selected_id = st.selectbox("Select Audit ID", options=[a.id for a in audits], format_func=lambda x: f"ID {x} - {next((a.domain for a in audits if a.id == x), '')}")
        
        if selected_id:
            selected_audit = next((a for a in audits if a.id == selected_id), None)
            if selected_audit:
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**URL:** {selected_audit.url}")
                    st.markdown(f"**Health Score:** {selected_audit.health_score}/100")
                    st.markdown(f"**Domain Age:** {selected_audit.domain_age}")
                    st.markdown(f"**Tech Stack:** {', '.join(selected_audit.tech_stack) if selected_audit.tech_stack else 'Standard'}")
                
                with col2:
                    st.markdown(f"**Emails Found:** {', '.join(selected_audit.emails_found[:3]) if selected_audit.emails_found else 'None'}")
                    st.markdown(f"**Audit Date:** {selected_audit.created_at}")
                
                if selected_audit.issues:
                    st.markdown("**Issues:**")
                    for issue in selected_audit.issues:
                        st.markdown(f"- {issue.get('title', 'Unknown Issue')}")
                
                if selected_audit.ai_email:
                    st.markdown("---")
                    st.markdown("**AI Generated Email:**")
                    st.text_area("Email", value=clean_text(selected_audit.ai_email), height=200, key=f"email_{selected_id}")
    else:
        st.info("No audits found. Run some audits to see them here!")

# --- TAB 4: COMPETITOR ANALYSIS ---
with tab4:
    st.markdown("### Competitor Analysis")
    st.markdown("Compare multiple websites side-by-side to identify competitive advantages and gaps.")
    
    # Input for competitor URLs
    st.markdown("#### Enter websites to compare (up to 5)")
    
    competitor_urls = []
    cols = st.columns(5)
    for i, col in enumerate(cols):
        with col:
            url_input = st.text_input(f"Website {i+1}", placeholder="example.com", key=f"comp_url_{i}")
            if url_input:
                competitor_urls.append(url_input)
    
    comparison_name = st.text_input("Comparison Group Name (optional)", placeholder="e.g., 'Q4 Competitor Review'")
    
    if st.button("Run Comparison Analysis", type="primary", key="run_comparison"):
        if len(competitor_urls) < 2:
            st.warning("Please enter at least 2 websites to compare.")
        else:
            comparison_results = []
            progress = st.progress(0)
            
            for i, url in enumerate(competitor_urls):
                with st.spinner(f"Analyzing {url}..."):
                    data = run_audit(url, OPENAI_API_KEY, GOOGLE_API_KEY)
                    save_audit_to_db(data, comparison_group=comparison_name if comparison_name else None)
                    comparison_results.append(data)
                    progress.progress((i + 1) / len(competitor_urls))
            
            st.success("Comparison complete!")
            
            # Display comparison table
            st.markdown("---")
            st.markdown("### Comparison Results")
            
            comp_data = []
            for data in comparison_results:
                domain = urlparse(data['url']).netloc.replace("www.", "")
                comp_data.append({
                    "Website": domain,
                    "Health Score": data['score'],
                    "PSI Score": data.get('psi', 'N/A'),
                    "Issues Count": len(data.get('issues', [])),
                    "Has Analytics": "Yes" if any("Analytics" in t for t in data.get('tech_stack', [])) else "No",
                    "Has Tracking": "Yes" if any("Pixel" in t for t in data.get('tech_stack', [])) else "No",
                    "Mobile Ready": "Yes" if not any("Not Mobile" in i.get('title', '') for i in data.get('issues', [])) else "No",
                    "SSL": "Yes" if not any("No SSL" in i.get('title', '') for i in data.get('issues', [])) else "No"
                })
            
            comp_df = pd.DataFrame(comp_data)
            st.dataframe(comp_df, use_container_width=True)
            
            # Visual comparison
            st.markdown("---")
            st.markdown("### Visual Comparison")
            
            # Health Score Chart
            chart_data = pd.DataFrame({
                "Website": [d["Website"] for d in comp_data],
                "Health Score": [d["Health Score"] for d in comp_data]
            })
            st.bar_chart(chart_data.set_index("Website"))
            
            # Winner analysis
            best_score = max(comp_data, key=lambda x: x["Health Score"]) if comp_data else None
            worst_score = min(comp_data, key=lambda x: x["Health Score"]) if comp_data else None
            
            st.markdown("---")
            col1, col2 = st.columns(2)
            with col1:
                if best_score:
                    st.success(f"**Best Performer:** {best_score['Website']} (Score: {best_score['Health Score']})")
            with col2:
                if worst_score:
                    st.error(f"**Needs Most Work:** {worst_score['Website']} (Score: {worst_score['Health Score']})")
            
            # Detailed breakdown per site
            st.markdown("---")
            st.markdown("### Detailed Issue Breakdown")
            for i, data in enumerate(comparison_results):
                domain = urlparse(data['url']).netloc.replace("www.", "")
                with st.expander(f"{domain} - {len(data.get('issues', []))} issues"):
                    if data.get('issues'):
                        for issue in data['issues']:
                            st.markdown(f"- **{issue['title']}**: {issue['impact']}")
                    else:
                        st.markdown("No critical issues found!")

# --- TAB 5: EMAIL OUTREACH ---
with tab5:
    st.markdown("### Email Outreach Center")
    st.markdown("Send personalized outreach emails to leads directly from the platform.")
    
    if not DB_AVAILABLE:
        st.error("Database connection required. Please ensure DATABASE_URL is configured to use this feature.")
        st.stop()
    
    # Email configuration notice
    smtp_configured = os.environ.get("SMTP_HOST") and os.environ.get("SMTP_USER")
    if not smtp_configured:
        st.warning("Email sending requires SMTP configuration. Add SMTP_HOST, SMTP_PORT, SMTP_USER, and SMTP_PASSWORD to your environment secrets to enable direct sending.")
    
    # Get leads for selection
    leads = get_leads()
    
    if leads:
        st.markdown("#### Select Lead to Contact")
        lead_options = {f"{l.domain} (Score: {l.health_score}, Rating: {l.opportunity_rating})": l for l in leads}
        selected_lead_name = st.selectbox("Choose a lead", options=list(lead_options.keys()))
        selected_lead = lead_options[selected_lead_name] if selected_lead_name else None
        
        if selected_lead:
            # Get latest audit for this lead
            audits_for_lead = get_audit_history(limit=1, search_query=selected_lead.domain)
            latest_audit = audits_for_lead[0] if audits_for_lead else None
            
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**Domain:** {selected_lead.domain}")
                st.markdown(f"**Health Score:** {selected_lead.health_score}")
                st.markdown(f"**Opportunity Rating:** {selected_lead.opportunity_rating}/15")
                st.markdown(f"**Status:** {selected_lead.status}")
            with col2:
                st.markdown(f"**Contact Email:** {selected_lead.email or 'Not found'}")
                st.markdown(f"**Created:** {selected_lead.created_at.strftime('%Y-%m-%d') if selected_lead.created_at else 'N/A'}")
                new_status = st.selectbox("Update Status", ["new", "contacted", "responded", "converted", "lost"], index=["new", "contacted", "responded", "converted", "lost"].index(selected_lead.status))
                if new_status != selected_lead.status:
                    if st.button("Update Status"):
                        if update_lead_status(selected_lead.id, new_status):
                            st.success("Status updated!")
                            st.rerun()
            
            st.markdown("---")
            st.markdown("#### Compose Email")
            
            # Pre-fill with AI-generated content if available
            default_email = ""
            if latest_audit and latest_audit.ai_email:
                default_email = clean_text(latest_audit.ai_email)
            
            recipient = st.text_input("Recipient Email", value=selected_lead.email or "", key="recipient_email")
            subject = st.text_input("Subject", value=f"Website Performance Review - {selected_lead.domain}", key="email_subject")
            body = st.text_area("Email Body", value=default_email, height=300, key="email_body")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Save as Draft", key="save_draft"):
                    if recipient and subject and body:
                        email_id = save_email_outreach(recipient, subject, body, selected_lead.id)
                        if email_id:
                            st.success(f"Draft saved (ID: {email_id})")
                        else:
                            st.error("Failed to save draft")
                    else:
                        st.warning("Please fill in all fields")
            
            with col2:
                if smtp_configured:
                    if st.button("Send Email", type="primary", key="send_email"):
                        if recipient and subject and body:
                            try:
                                # SMTP sending
                                smtp_host = os.environ.get("SMTP_HOST")
                                smtp_port = int(os.environ.get("SMTP_PORT", 587))
                                smtp_user = os.environ.get("SMTP_USER")
                                smtp_pass = os.environ.get("SMTP_PASSWORD")
                                
                                msg = MIMEMultipart()
                                msg['From'] = smtp_user
                                msg['To'] = recipient
                                msg['Subject'] = subject
                                msg.attach(MIMEText(body, 'plain'))
                                
                                with smtplib.SMTP(smtp_host, smtp_port) as server:
                                    server.starttls()
                                    server.login(smtp_user, smtp_pass)
                                    server.send_message(msg)
                                
                                # Save and mark as sent
                                email_id = save_email_outreach(recipient, subject, body, selected_lead.id)
                                if email_id:
                                    mark_email_sent(email_id)
                                    update_lead_status(selected_lead.id, "contacted")
                                
                                st.success("Email sent successfully!")
                            except Exception as e:
                                st.error(f"Failed to send email: {str(e)}")
                        else:
                            st.warning("Please fill in all fields")
                else:
                    st.info("Configure SMTP to enable sending")
    else:
        st.info("No leads found. Run some audits to generate leads!")

# --- TAB 6: SCHEDULED AUDITS ---
with tab6:
    st.markdown("### Scheduled Re-Audits")
    st.markdown("Set up automated periodic audits to track website improvements over time.")
    
    if not DB_AVAILABLE:
        st.error("Database connection required. Please ensure DATABASE_URL is configured to use this feature.")
        st.stop()
    
    # Get audit history for scheduling
    all_audits = get_audit_history(limit=100)
    
    if all_audits:
        st.markdown("#### Schedule New Re-Audit")
        
        # Get unique domains
        unique_domains = list(set(a.domain for a in all_audits))
        selected_domain = st.selectbox("Select domain to schedule", unique_domains)
        
        # Find most recent audit for this domain
        domain_audit = next((a for a in all_audits if a.domain == selected_domain), None)
        
        if domain_audit:
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**Current Health Score:** {domain_audit.health_score}")
                st.markdown(f"**Last Audited:** {domain_audit.created_at.strftime('%Y-%m-%d %H:%M') if domain_audit.created_at else 'N/A'}")
            with col2:
                interval = st.selectbox("Re-audit Interval", [
                    ("Weekly", 7),
                    ("Bi-weekly", 14),
                    ("Monthly", 30),
                    ("Quarterly", 90)
                ], format_func=lambda x: x[0])
                
                if st.button("Schedule Re-Audit", type="primary"):
                    if schedule_audit(domain_audit.id, interval[1]):
                        st.success(f"Scheduled {selected_domain} for {interval[0].lower()} re-audits!")
                    else:
                        st.error("Failed to schedule audit")
        
        st.markdown("---")
        st.markdown("#### Currently Scheduled Audits")
        
        scheduled = get_scheduled_audits()
        if scheduled:
            for idx, audit in enumerate(scheduled):
                with st.container():
                    col1, col2, col3, col4, col5 = st.columns([2, 1, 1, 1, 1])
                    with col1:
                        st.markdown(f"**{audit.domain}**")
                    with col2:
                        st.markdown(f"Score: {audit.health_score}")
                    with col3:
                        st.markdown(f"Every {audit.schedule_interval_days}d")
                    with col4:
                        next_run = audit.next_scheduled_run.strftime("%Y-%m-%d") if audit.next_scheduled_run else "Pending"
                        is_due = audit.next_scheduled_run and audit.next_scheduled_run <= datetime.utcnow()
                        if is_due:
                            st.markdown(f"**Due Now**")
                        else:
                            st.markdown(f"Next: {next_run}")
                    with col5:
                        if st.button("Run Now", key=f"run_sched_{audit.id}"):
                            with st.spinner(f"Running scheduled audit for {audit.domain}..."):
                                new_data, old_score = run_scheduled_audit(audit.id, OPENAI_API_KEY, GOOGLE_API_KEY)
                                if new_data and old_score is not None:
                                    score_diff = new_data['score'] - old_score
                                    st.success(f"Audit complete! Score: {new_data['score']}/100 ({score_diff:+d})")
                                    st.rerun()
                                else:
                                    st.error("Failed to run scheduled audit")
                    st.divider()
        else:
            st.info("No scheduled audits. Use the form above to schedule periodic re-audits.")
        
        # Manual re-run option
        st.markdown("---")
        st.markdown("#### Quick Re-Audit")
        st.markdown("Run an immediate re-audit on any previously audited domain.")
        
        reaudit_domain = st.selectbox("Select domain for quick re-audit", unique_domains, key="reaudit_select")
        if st.button("Run Re-Audit Now"):
            # Find the original URL
            original_audit = next((a for a in all_audits if a.domain == reaudit_domain), None)
            if original_audit:
                with st.spinner(f"Re-auditing {reaudit_domain}..."):
                    new_data = run_audit(original_audit.url, OPENAI_API_KEY, GOOGLE_API_KEY)
                    save_audit_to_db(new_data)
                    
                    # Show comparison
                    score_diff = new_data['score'] - original_audit.health_score
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Previous Score", f"{original_audit.health_score}/100")
                    with col2:
                        st.metric("New Score", f"{new_data['score']}/100", delta=f"{score_diff:+d}")
                    with col3:
                        if score_diff > 0:
                            st.success("Improvement!")
                        elif score_diff < 0:
                            st.error("Decline")
                        else:
                            st.info("No change")
    else:
        st.info("No audits found. Run some audits first to enable scheduling!")
