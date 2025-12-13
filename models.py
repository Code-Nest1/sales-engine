import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime, Boolean, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

DATABASE_URL = os.environ.get("DATABASE_URL")

# Fallback to a local SQLite file if no DATABASE_URL is provided. This
# makes the app usable out-of-the-box without external DB configuration.
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///./sales_engine.db"

# For SQLite we must set check_same_thread=False to allow access from
# different threads (Streamlit uses multiple threads/workers).
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite:") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Audit(Base):
    __tablename__ = "audits"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(500), nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    health_score = Column(Integer, default=100)
    psi_score = Column(Integer, nullable=True)
    domain_age = Column(String(100), nullable=True)
    tech_stack = Column(JSON, default=list)
    issues = Column(JSON, default=list)
    emails_found = Column(JSON, default=list)
    ai_summary = Column(Text, nullable=True)
    ai_impact = Column(Text, nullable=True)
    ai_solutions = Column(Text, nullable=True)
    ai_email = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # User tracking - associates audit with user who created it
    username = Column(String(150), nullable=True, index=True)
    
    # Source tracking - single, bulk, or manual
    source = Column(String(50), default="single")
    
    # For competitor analysis grouping
    comparison_group = Column(String(100), nullable=True)
    
    # For scheduled re-audits
    is_scheduled = Column(Boolean, default=False)
    schedule_interval_days = Column(Integer, nullable=True)
    last_scheduled_run = Column(DateTime, nullable=True)
    next_scheduled_run = Column(DateTime, nullable=True)

class Lead(Base):
    __tablename__ = "leads"
    
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), nullable=False, index=True)
    email = Column(String(255), nullable=True)
    company_name = Column(String(255), nullable=True)
    phone = Column(String(50), nullable=True)  # Extended for international formats
    address = Column(Text, nullable=True)
    place_id = Column(String(500), nullable=True)  # Google Places ID
    city = Column(String(100), nullable=True)
    state = Column(String(100), nullable=True)
    zipcode = Column(String(20), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    health_score = Column(Integer, nullable=True)
    opportunity_rating = Column(Integer, default=0)
    industry = Column(String(100), nullable=True)  # Auto-detected or manual
    company_size = Column(String(50), nullable=True)  # Small, Medium, Large, Enterprise
    estimated_revenue = Column(String(50), nullable=True)
    services_needed = Column(JSON, default=list)  # Array of service scores
    service_priorities = Column(JSON, default=dict)  # {"website_dev": 85, "seo": 90, ...}
    status = Column(String(50), default="new")  # Legacy: new, contacted, responded, converted, lost
    notes = Column(Text, nullable=True)
    ai_enrichment = Column(JSON, nullable=True)  # Stores AI analysis
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # =========================================================================
    # CRM FIELDS - Added for proper lead management workflow
    # =========================================================================
    
    # Outreach tracking
    approached = Column(Boolean, default=False, nullable=False)  # Has lead been contacted?
    approached_date = Column(DateTime, nullable=True)  # When first approached
    follow_up_date = Column(DateTime, nullable=True)  # Scheduled follow-up
    
    # Lead qualification
    lead_status = Column(String(20), default="warm")  # hot, warm, cold
    interested = Column(String(20), default="maybe")  # yes, no, maybe
    
    # Pipeline management
    pipeline_stage = Column(String(50), default="new")  # new, contacted, follow-up, closed
    assigned_user = Column(String(150), nullable=True)  # Username of assigned salesperson
    
    # Source tracking
    source = Column(String(50), default="single")  # single, bulk, manual
    
    # Link to most recent audit
    last_audit_id = Column(Integer, nullable=True)  # Reference to most recent audit

class EmailOutreach(Base):
    __tablename__ = "email_outreach"
    
    id = Column(Integer, primary_key=True, index=True)
    lead_id = Column(Integer, ForeignKey("leads.id"), nullable=True)
    recipient_email = Column(String(255), nullable=False)
    subject = Column(String(500), nullable=False)
    body = Column(Text, nullable=False)
    status = Column(String(50), default="draft")  # draft, sent, opened, replied
    sent_at = Column(DateTime, nullable=True)
    opened_at = Column(DateTime, nullable=True)
    replied_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class BulkScan(Base):
    __tablename__ = "bulk_scans"
    
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(255), nullable=False)  # Unique session identifier
    status = Column(String(50), default="running")  # running, paused, completed, stopped
    total_urls = Column(Integer, nullable=False)
    processed_urls = Column(Integer, default=0)
    urls = Column(JSON, default=list)  # All URLs to scan
    results = Column(JSON, default=dict)  # {"url": audit_id}
    paused_at_index = Column(Integer, default=0)  # Resume point
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(150), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)
    # API Keys stored in encrypted format
    api_keys = Column(JSON, default=dict)  # {"openai": "encrypted_key", "google": "...", "slack": "..."}
    api_keys_updated_at = Column(DateTime, nullable=True)
    # SMTP settings stored per-user (some encrypted, some not)
    smtp_settings = Column(JSON, default=dict)  # {"host": "", "port": 587, "user": "", "pass": "encrypted"}
    created_at = Column(DateTime, default=datetime.utcnow)

def init_db():
    """Initialize database tables."""
    if engine:
        Base.metadata.create_all(bind=engine)
        # Migrate existing tables to add missing columns
        migrate_leads_table()
        migrate_users_table()
        migrate_audits_table()
        return True
    return False


def migrate_audits_table():
    """Add username and source columns to audits table if they don't exist."""
    if not engine:
        return
    
    inspector = __import__('sqlalchemy').inspect(engine)
    if 'audits' not in inspector.get_table_names():
        return
    
    audits_columns = [c['name'] for c in inspector.get_columns('audits')]
    
    with engine.connect() as conn:
        # Add username column for user tracking
        if 'username' not in audits_columns:
            try:
                conn.execute(__import__('sqlalchemy').text('ALTER TABLE audits ADD COLUMN username VARCHAR(150)'))
                conn.commit()
            except Exception:
                pass
        
        # Add source column for tracking origin (single/bulk/manual)
        if 'source' not in audits_columns:
            try:
                conn.execute(__import__('sqlalchemy').text('ALTER TABLE audits ADD COLUMN source VARCHAR(50) DEFAULT "single"'))
                conn.commit()
            except Exception:
                pass
        
        # Create indexes for faster queries
        for idx_name, idx_col in [
            ('ix_audits_username', 'username'),
            ('ix_audits_domain', 'domain'),
            ('ix_audits_created_at', 'created_at')
        ]:
            try:
                conn.execute(__import__('sqlalchemy').text(f'CREATE INDEX IF NOT EXISTS {idx_name} ON audits ({idx_col})'))
                conn.commit()
            except Exception:
                pass

def migrate_users_table():
    """Add api_keys, api_keys_updated_at, and smtp_settings columns to users table if they don't exist."""
    if not engine:
        return
    
    inspector = __import__('sqlalchemy').inspect(engine)
    if 'users' not in inspector.get_table_names():
        return
    
    users_columns = [c['name'] for c in inspector.get_columns('users')]
    
    # Add api_keys column if it doesn't exist
    with engine.connect() as conn:
        if 'api_keys' not in users_columns:
            try:
                conn.execute(__import__('sqlalchemy').text('ALTER TABLE users ADD COLUMN api_keys JSON DEFAULT "{}"'))
                conn.commit()
            except Exception:
                pass
        
        if 'api_keys_updated_at' not in users_columns:
            try:
                conn.execute(__import__('sqlalchemy').text('ALTER TABLE users ADD COLUMN api_keys_updated_at DATETIME'))
                conn.commit()
            except Exception:
                pass
        
        # Add smtp_settings column for per-user SMTP configuration
        if 'smtp_settings' not in users_columns:
            try:
                conn.execute(__import__('sqlalchemy').text('ALTER TABLE users ADD COLUMN smtp_settings JSON DEFAULT "{}"'))
                conn.commit()
            except Exception:
                pass

def migrate_leads_table():
    """Add missing columns to leads table if they don't exist."""
    if not engine:
        return
    
    inspector = __import__('sqlalchemy').inspect(engine)
    leads_columns = [c['name'] for c in inspector.get_columns('leads')] if 'leads' in inspector.get_table_names() else []
    
    # List of columns that should exist (including new CRM fields)
    required_columns = {
        # Original fields
        'phone': 'ALTER TABLE leads ADD COLUMN phone VARCHAR(50)',
        'address': 'ALTER TABLE leads ADD COLUMN address TEXT',
        'place_id': 'ALTER TABLE leads ADD COLUMN place_id VARCHAR(500)',
        'city': 'ALTER TABLE leads ADD COLUMN city VARCHAR(100)',
        'state': 'ALTER TABLE leads ADD COLUMN state VARCHAR(100)',
        'zipcode': 'ALTER TABLE leads ADD COLUMN zipcode VARCHAR(20)',
        'latitude': 'ALTER TABLE leads ADD COLUMN latitude FLOAT',
        'longitude': 'ALTER TABLE leads ADD COLUMN longitude FLOAT',
        'industry': 'ALTER TABLE leads ADD COLUMN industry VARCHAR(100)',
        'company_size': 'ALTER TABLE leads ADD COLUMN company_size VARCHAR(50)',
        'estimated_revenue': 'ALTER TABLE leads ADD COLUMN estimated_revenue VARCHAR(50)',
        'services_needed': 'ALTER TABLE leads ADD COLUMN services_needed JSON',
        'service_priorities': 'ALTER TABLE leads ADD COLUMN service_priorities JSON',
        'status': 'ALTER TABLE leads ADD COLUMN status VARCHAR(50) DEFAULT "new"',
        'notes': 'ALTER TABLE leads ADD COLUMN notes TEXT',
        'ai_enrichment': 'ALTER TABLE leads ADD COLUMN ai_enrichment JSON',
        'opportunity_rating': 'ALTER TABLE leads ADD COLUMN opportunity_rating INTEGER DEFAULT 0',
        'updated_at': 'ALTER TABLE leads ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP',
        
        # NEW CRM FIELDS
        'approached': 'ALTER TABLE leads ADD COLUMN approached BOOLEAN DEFAULT 0',
        'approached_date': 'ALTER TABLE leads ADD COLUMN approached_date DATETIME',
        'follow_up_date': 'ALTER TABLE leads ADD COLUMN follow_up_date DATETIME',
        'lead_status': 'ALTER TABLE leads ADD COLUMN lead_status VARCHAR(20) DEFAULT "warm"',
        'interested': 'ALTER TABLE leads ADD COLUMN interested VARCHAR(20) DEFAULT "maybe"',
        'pipeline_stage': 'ALTER TABLE leads ADD COLUMN pipeline_stage VARCHAR(50) DEFAULT "new"',
        'assigned_user': 'ALTER TABLE leads ADD COLUMN assigned_user VARCHAR(150)',
        'source': 'ALTER TABLE leads ADD COLUMN source VARCHAR(50) DEFAULT "single"',
        'last_audit_id': 'ALTER TABLE leads ADD COLUMN last_audit_id INTEGER',
    }
    
    # Add missing columns
    with engine.connect() as conn:
        for col_name, sql in required_columns.items():
            if col_name not in leads_columns:
                try:
                    conn.execute(__import__('sqlalchemy').text(sql))
                    conn.commit()
                except Exception as e:
                    # Column might already exist or be incompatible, continue
                    pass
        
        # Create index on domain for faster lookups
        try:
            conn.execute(__import__('sqlalchemy').text('CREATE INDEX IF NOT EXISTS ix_leads_domain ON leads (domain)'))
            conn.commit()
        except Exception:
            pass

def get_db():
    """Get database session."""
    if SessionLocal:
        db = SessionLocal()
        try:
            return db
        except:
            db.close()
            raise
    return None
