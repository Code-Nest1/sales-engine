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
    domain = Column(String(255), nullable=False)
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
    created_at = Column(DateTime, default=datetime.utcnow)
    
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
    domain = Column(String(255), nullable=False)
    email = Column(String(255), nullable=True)
    company_name = Column(String(255), nullable=True)
    phone = Column(String(20), nullable=True)
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
    status = Column(String(50), default="new")  # new, contacted, responded, converted, lost
    notes = Column(Text, nullable=True)
    ai_enrichment = Column(JSON, nullable=True)  # Stores AI analysis
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    created_at = Column(DateTime, default=datetime.utcnow)

def init_db():
    """Initialize database tables."""
    if engine:
        Base.metadata.create_all(bind=engine)
        # Migrate existing tables to add missing columns
        migrate_leads_table()
        return True
    return False

def migrate_leads_table():
    """Add missing columns to leads table if they don't exist."""
    if not engine:
        return
    
    inspector = __import__('sqlalchemy').inspect(engine)
    leads_columns = [c['name'] for c in inspector.get_columns('leads')] if 'leads' in inspector.get_table_names() else []
    
    # List of columns that should exist
    required_columns = {
        'phone': 'ALTER TABLE leads ADD COLUMN phone VARCHAR(20)',
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
