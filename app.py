import streamlit as st
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import pandas as pd
from fpdf import FPDF
from datetime import datetime
import time
import re
import whois
from openai import OpenAI
import socket

# --- CONFIGURATION ---
st.set_page_config(page_title="Code Nest Sales Engine", layout="wide", page_icon="🦅")

# --- BRANDING CONSTANTS ---
COMPANY_NAME = "Code Nest"
COMPANY_TAGLINE = "Launch. Scale. Optimize."
CONTACT_EMAIL = "services@codenest.agency"
COMPANY_COLOR = (0, 102, 204) # Code Nest Blue

# --- SIDEBAR CONFIG ---
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/2362/2362334.png", width=50) # Placeholder Eagle Icon
    st.header("🦅 Engine Settings")
    st.caption("Configure your intelligence sources.")
    
    openai_input = st.text_input("OpenAI API Key (Required for Pitch)", type="password")
    google_input = st.text_input("Google PageSpeed Key (Optional)", type="password")
    
    OPENAI_API_KEY = openai_input.strip() if openai_input else None
    GOOGLE_API_KEY = google_input.strip() if google_input else None
    
    st.divider()
    st.info("System Status: **Active**\n\nVersion: 3.0 Enterprise")

# --- HELPER FUNCTIONS ---

def clean_text(text):
    """Sanitizes text for PDF generation to prevent encoding crashes."""
    if not text: return ""
    # Replace common smart quotes/dashes
    text = text.replace('“', '"').replace('”', '"').replace('’', "'").replace('–', '-')
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
    except:
        pass
    return "Unknown", 0

def check_broken_links(url, soup, limit=10):
    """Scans the first few internal links to see if they are broken."""
    broken = 0
    checked = 0
    links = soup.find_all('a', href=True)
    
    for link in links[:limit]:
        href = link['href']
        full_url = urljoin(url, href)
        if urlparse(full_url).netloc == urlparse(url).netloc: # Internal only
            checked += 1
            try:
                r = requests.head(full_url, timeout=3)
                if r.status_code >= 400:
                    broken += 1
            except:
                broken += 1
    return broken, checked

def get_google_metrics(url, api_key):
    """Fetches Core Web Vitals from Google PSI."""
    if not api_key: return None, "No API Key"
    
    api_url = f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url={url}&strategy=mobile&key={api_key}"
    try:
        r = requests.get(api_url, timeout=45) # Long timeout for Google
        if r.status_code == 200:
            data = r.json()
            lh = data['lighthouseResult']
            score = lh['categories']['performance']['score'] * 100
            
            # Extract Core Web Vitals
            metrics = {
                "score": int(score),
                "lcp": lh['audits']['largest-contentful-paint']['displayValue'],
                "cls": lh['audits']['cumulative-layout-shift']['displayValue'],
                "fcp": lh['audits']['first-contentful-paint']['displayValue']
            }
            return metrics, "Success"
        else:
            return None, f"Google Error: {r.status_code}"
    except Exception as e:
        return None, str(e)

# --- AI BRAIN ---

def get_ai_consultation(url, data, api_key):
    """Uses GPT-4o-mini to act as a Senior Consultant."""
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
    
    TASK 1: Write an Executive Summary (2 sentences max) describing the site's state.
    TASK 2: Summarize the Business Impact (Financial/Brand loss) in 2 bullet points.
    TASK 3: List 3 specific Code Nest services to fix these issues.
    TASK 4: Write a high-converting Cold Email to the owner (Subject + Body). Tone: Professional, Expert, Helpful.
    
    Output format: Return the 4 sections clearly separated by '###'.
    """

    try:
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}]
        )
        content = response.choices[0].message.content
        parts = content.split("###")
        
        # Safe fallback if split fails
        return {
            "summary": parts[1] if len(parts) > 1 else "Analysis generated.",
            "impact": parts[2] if len(parts) > 2 else "Potential revenue loss detected.",
            "solutions": parts[3] if len(parts) > 3 else "Optimization & Redesign.",
            "email": parts[4] if len(parts) > 4 else "Contact us for details."
        }
    except Exception as e:
        return {"summary": "AI Error", "impact": "AI Error", "solutions": "AI Error", "email": str(e)}

# --- MAIN AUDIT LOGIC ---

def run_audit(url):
    if not url.startswith('http'): url = 'http://' + url
    
    data = {
        "url": url,
        "score": 100,
        "issues": [],
        "tech_stack": [],
        "emails": [],
        "meta": {},
        "psi": None,
        "psi_error": None,
        "domain_age": "Unknown"
    }

    try:
        # 1. CONNECTIVITY
        start = time.time()
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=20)
        load_time = time.time() - start
        
        html = response.text.lower()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 2. BASIC INFO
        data['domain_age'] = get_domain_age(url)[0]
        data['emails'] = list(set(re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", html)))

        # 3. TECH DETECTION
        if "wp-content" in html: 
            data['tech_stack'].append("WordPress")
            data['score'] -= 5
            data['issues'].append({"title": "WordPress Detected", "impact": "Requires monthly security maintenance.", "solution": "Code Nest Maintenance Plan"})
        elif "shopify" in html: data['tech_stack'].append("Shopify")
        elif "wix" in html: 
            data['tech_stack'].append("Wix")
            data['score'] -= 10
            data['issues'].append({"title": "Builder Platform Limitations", "impact": "Wix limits SEO scaling and customization.", "solution": "Migration to Custom/WordPress"})
        
        if "react" in html: data['tech_stack'].append("React")
        if "cloudflare" in str(response.headers): data['tech_stack'].append("Cloudflare CDN")

        # 4. MARKETING
        pixels = []
        if "fbq(" in html: pixels.append("Facebook Pixel")
        if "gtag(" in html or "ua-" in html: pixels.append("Google Analytics")
        if "hotjar" in html: pixels.append("Hotjar")
        
        if not pixels:
            data['score'] -= 15
            data['issues'].append({"title": "Zero Tracking Installed", "impact": "You are flying blind. No data on customer behavior.", "solution": "Analytics & Pixel Setup"})
        else:
            data['tech_stack'].extend(pixels)

        # 5. SEO BASICS
        title = soup.title.string if soup.title else ""
        if len(title) < 10:
            data['score'] -= 10
            data['issues'].append({"title": "Weak Title Tag", "impact": "Google ignores pages with poor titles.", "solution": "On-Page SEO Optimization"})
        
        meta_desc = soup.find("meta", attrs={"name": "description"})
        if not meta_desc:
            data['score'] -= 10
            data['issues'].append({"title": "Missing Meta Description", "impact": "Low click-through rate from Google.", "solution": "SEO Content Strategy"})

        h1 = soup.find("h1")
        if not h1:
            data['score'] -= 5
            data['issues'].append({"title": "Missing H1 Header", "impact": "Confuses search engines about page topic.", "solution": "Technical SEO Fixes"})

        # 6. SECURITY HEADERS
        security_headers = ['X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security']
        missing_headers = [h for h in security_headers if h not in response.headers]
        if missing_headers:
            data['score'] -= 5
            data['issues'].append({"title": "Missing Security Headers", "impact": "Vulnerable to clickjacking/attacks.", "solution": "Security Hardening"})

        # 7. PERFORMANCE (PSI)
        psi_data, psi_msg = get_google_metrics(url, GOOGLE_API_KEY)
        if psi_data:
            data['psi'] = psi_data
            if psi_data['score'] < 50:
                data['score'] -= 20
                data['issues'].append({"title": f"Critical Speed Score ({psi_data['score']}/100)", "impact": "Users abandon slow sites immediately.", "solution": "Core Web Vitals Optimization"})
        else:
            data['psi_error'] = psi_msg
            if load_time > 3.0:
                data['score'] -= 10
                data['issues'].append({"title": "Slow Server Response", "impact": f"Load time {round(load_time,2)}s is too slow.", "solution": "Speed Optimization"})

        # 8. BROKEN LINKS
        broken, checked = check_broken_links(url, soup)
        if broken > 0:
            data['score'] -= 10
            data['issues'].append({"title": "Broken Internal Links", "impact": "Frustrates users and hurts SEO rankings.", "solution": "Quality Assurance Audit"})

        # 9. AI CONSULTATION
        data['ai'] = get_ai_consultation(url, data, OPENAI_API_KEY)

    except Exception as e:
        data['error'] = str(e)

    return data

# --- PDF GENERATOR ---

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 24)
        self.set_text_color(*COMPANY_COLOR)
        self.cell(0, 10, clean_text(COMPANY_NAME), 0, 1, 'L')
        self.set_font('Arial', 'I', 11)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, clean_text(COMPANY_TAGLINE), 0, 1, 'L')
        self.set_draw_color(*COMPANY_COLOR)
        self.set_line_width(1)
        self.line(10, 30, 200, 30)
        self.ln(10)

    def section_title(self, label):
        self.ln(5)
        self.set_font('Arial', 'B', 14)
        self.set_fill_color(240, 248, 255) # AliceBlue
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

    # --- COVER ---
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, f"Website Audit: {clean_text(data['url'])}", 0, 1)
    
    score_color = (0, 128, 0) if data['score'] > 70 else (200, 0, 0)
    pdf.set_text_color(*score_color)
    pdf.cell(0, 10, f"Health Score: {data['score']}/100", 0, 1)
    
    pdf.set_text_color(0, 0, 0)
    pdf.set_font('Arial', '', 10)
    pdf.cell(0, 6, f"Domain Age: {data.get('domain_age', 'Unknown')}", 0, 1)
    if data['emails']:
        pdf.cell(0, 6, f"Contacts Found: {', '.join(data['emails'][:3])}", 0, 1)
    pdf.ln(5)

    # --- EXECUTIVE SUMMARY (AI) ---
    if data.get('ai'):
        pdf.section_title("1. Executive Strategy Summary")
        pdf.set_font('Arial', 'I', 10)
        pdf.multi_cell(0, 6, clean_text(data['ai'].get('summary', '').strip()))
        pdf.ln(2)

    # --- TECH STACK ---
    pdf.section_title("2. Technology & Infrastructure")
    tech = ", ".join(data['tech_stack']) if data['tech_stack'] else "Standard HTML (No CMS Detected)"
    pdf.chapter_body(f"Detected Stack: {tech}")

    # --- PERFORMANCE ---
    pdf.section_title("3. Performance & Speed")
    if data.get('psi'):
        p = data['psi']
        pdf.chapter_body(f"Google Mobile Score: {p['score']}/100")
        pdf.chapter_body(f"Core Vitals: LCP: {p['lcp']} | CLS: {p['cls']} | FCP: {p['fcp']}")
    else:
        pdf.chapter_body("Google API Data: Not Available (Check API Key or Limits)")

    # --- CRITICAL ISSUES ---
    pdf.section_title("4. Critical Findings & Business Impact")
    for issue in data['issues']:
        pdf.set_font('Arial', 'B', 10)
        pdf.set_text_color(180, 0, 0)
        pdf.cell(0, 6, f"[!] {clean_text(issue['title'])}", 0, 1)
        
        pdf.set_font('Arial', '', 10)
        pdf.set_text_color(50, 50, 50)
        pdf.multi_cell(0, 5, f"Business Impact: {clean_text(issue['impact'])}")
        
        pdf.set_text_color(0, 102, 51)
        pdf.multi_cell(0, 5, f"Code Nest Solution: {clean_text(issue['solution'])}")
        pdf.ln(3)

    # --- AI SOLUTIONS ---
    if data.get('ai'):
        pdf.section_title("5. Recommended Action Plan")
        pdf.chapter_body(clean_text(data['ai'].get('solutions', '').strip()))

    return pdf.output(dest='S').encode('latin-1')

# --- UI LAYER ---

tab1, tab2 = st.tabs(["🚀 Single Audit", "📂 Bulk Processor"])

with tab1:
    st.markdown("### Run a Deep Diagnostic")
    url = st.text_input("Website URL", placeholder="example.com")
    
    if st.button("Analyze Website"):
        if not url:
            st.warning("Please enter a URL.")
        else:
            with st.spinner("Initializing Agents... Scanning Tech... Querying Google... Writing Report..."):
                data = run_audit(url)
                
                if "error" in data:
                    st.error(f"Scan Failed: {data['error']}")
                else:
                    # METRICS ROW
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Health Score", f"{data['score']}/100")
                    
                    psi_val = data['psi']['score'] if data.get('psi') else "N/A"
                    c2.metric("Google Speed", psi_val)
                    
                    c3.metric("Issues Found", len(data['issues']))
                    c4.metric("Domain Age", data['domain_age'])
                    
                    # AI INSIGHTS
                    if data.get('ai'):
                        st.success("✅ AI Strategic Analysis Complete")
                        with st.expander("Show AI Sales Email", expanded=True):
                            st.text_area("Cold Email Draft", value=clean_text(data['ai']['email']), height=250)
                    
                    # DOWNLOAD
                    try:
                        pdf_bytes = generate_pdf(data)
                        st.download_button(
                            "📥 Download Code Nest Proposal (PDF)",
                            pdf_bytes,
                            f"CodeNest_Audit_{urlparse(url).netloc}.pdf",
                            "application/pdf",
                            type="primary"
                        )
                    except Exception as e:
                        st.error(f"PDF Generation Error: {e}")

with tab2:
    st.markdown("### Bulk Lead Qualifier")
    st.info("Upload a CSV with a column named **'Website'**.")
    uploaded = st.file_uploader("Upload CSV", type="csv")
    
    if uploaded and st.button("Process Batch"):
        df = pd.read_csv(uploaded)
        if "Website" not in df.columns:
            st.error("CSV must have a 'Website' column.")
        else:
            results = []
            progress = st.progress(0)
            status = st.empty()
            
            for i, row_site in enumerate(df['Website']):
                status.text(f"Auditing {row_site}...")
                d = run_audit(row_site.strip())
                
                # Opportunity Score Logic
                opp_score = 0
                if d['score'] < 50: opp_score += 5
                if not any("Pixel" in t for t in d['tech_stack']): opp_score += 3
                if "WordPress" in d['tech_stack']: opp_score += 2
                
                results.append({
                    "Website": row_site,
                    "Health": d['score'],
                    "GoogleSpeed": d['psi']['score'] if d.get('psi') else "N/A",
                    "Opp_Rating": opp_score,
                    "Emails": ", ".join(d['emails']),
                    "Issues": len(d['issues'])
                })
                progress.progress((i+1)/len(df))
            
            status.success("Batch Complete!")
            res_df = pd.DataFrame(results)
            st.dataframe(res_df.sort_values(by="Opp_Rating", ascending=False))
            
            csv = res_df.to_csv(index=False).encode('utf-8')
            st.download_button("Download Enriched Leads", csv, "CodeNest_Leads.csv", "text/csv")