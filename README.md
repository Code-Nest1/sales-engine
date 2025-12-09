# Code Nest Sales Engine

This workspace contains a Streamlit-based website auditing and lead-generation platform.

Features:
- Single-site audits with AI-driven recommendations and downloadable PDF reports
- Bulk processing of websites from CSV and exportable lead lists
- Optional database persistence (SQLAlchemy) for audit history, leads, scheduled audits
- Competitor analysis, email outreach (SMTP), and scheduled re-audits

Quick start
1. Create and activate a Python virtual environment (recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Configure environment variables as needed (optional but recommended):

- `OPENAI_API_KEY` — your OpenAI API key (used for AI consultation)
- `GOOGLE_API_KEY` — Google PageSpeed Insights API key (optional)
- `DATABASE_URL` — SQLAlchemy DB URL (e.g., `postgresql+psycopg2://user:pass@host:5432/dbname`) to enable history and scheduling
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` — configure to enable direct email sending

4. Run the app:

```bash
streamlit run app.py
```

Notes
- If you don't set `DATABASE_URL`, database features will be disabled but audit and PDF generation still work.
 - If you don't set `DATABASE_URL`, the app will fall back to a local SQLite database file `sales_engine.db` in the workspace root. This enables audit history, leads, and scheduling without external DB setup.
- The app uses `fpdf` and encodes text to `latin-1` for PDF stability; non-Latin characters may be replaced.

If you want, I can run a smoke test (install dependencies and start the app) — tell me if you want me to proceed.
