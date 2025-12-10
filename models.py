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
        return True
    return False

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
