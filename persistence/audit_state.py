"""
Audit State Persistence Module
==============================

Provides robust persistence for audit data across:
- Session state (memory)
- Disk cache (JSON files)
- Database (SQLite via SQLAlchemy)

This ensures audit results survive refresh, navigation, and logout.

Functions:
----------
- persist_audit_data(audit_id, audit_data): Save audit to all layers
- load_audit_data(audit_id): Load from cache or rebuild from DB
- get_current_audit(): Get the currently selected audit
- set_current_audit(audit_id): Set the current audit
- clear_current_audit(): Clear current audit selection

Author: Code Nest LLC
"""

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import streamlit as st

# Thread lock for file operations
_file_lock = threading.Lock()

# Cache directory
CACHE_DIR = Path(__file__).parent.parent / ".cache"
AUDIT_CACHE_FILE = CACHE_DIR / "audit_cache.json"

# Ensure cache directory exists
CACHE_DIR.mkdir(exist_ok=True)

# Logger
logger = logging.getLogger("sales_engine.persistence")


def _sanitize_domain(domain: str) -> str:
    """Sanitize domain name for use as cache key."""
    if not domain:
        return ""
    # Remove protocol and www
    domain = domain.lower().strip()
    if domain.startswith(('http://', 'https://')):
        try:
            domain = urlparse(domain).netloc
        except Exception:
            pass
    domain = domain.replace('www.', '')
    # Remove invalid characters
    domain = ''.join(c for c in domain if c.isalnum() or c in '.-_')
    return domain[:100]  # Limit length


def _load_audit_cache() -> Dict[str, Any]:
    """Load audit cache from disk with thread safety."""
    with _file_lock:
        try:
            if AUDIT_CACHE_FILE.exists():
                return json.loads(AUDIT_CACHE_FILE.read_text())
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load audit cache: {e}")
        return {}


def _save_audit_cache(cache: Dict[str, Any]) -> bool:
    """Save audit cache to disk with thread safety."""
    with _file_lock:
        try:
            AUDIT_CACHE_FILE.write_text(json.dumps(cache, indent=2, default=str))
            return True
        except IOError as e:
            logger.error(f"Failed to save audit cache: {e}")
            return False


def _get_default_audit_data() -> Dict[str, Any]:
    """Return default audit data structure with all required fields."""
    return {
        'url': '',
        'domain': '',
        'score': 0,
        'psi': 'N/A',
        'domain_age': 'Unknown',
        'tech_stack': [],
        'issues': [],
        'raw_html': '',
        'ai': {
            'summary': 'No summary available',
            'impact': 'No impact assessment available',
            'solutions': 'No solutions available',
            'email': 'No email draft available'
        },
        'audit_id': None,
        'created_at': None,
        'username': None,
        'source': 'single'
    }


def _ensure_audit_fields(audit_data: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure all required fields exist in audit data (auto-heal)."""
    if not audit_data:
        return _get_default_audit_data()
    
    defaults = _get_default_audit_data()
    
    # Merge with defaults (keep existing values, add missing)
    for key, value in defaults.items():
        if key not in audit_data:
            audit_data[key] = value
        elif key == 'ai' and isinstance(audit_data.get('ai'), dict):
            # Ensure AI sub-fields exist
            for ai_key, ai_value in defaults['ai'].items():
                if ai_key not in audit_data['ai']:
                    audit_data['ai'][ai_key] = ai_value
    
    return audit_data


def get_audit_from_db(audit_id: int) -> Optional[Any]:
    """
    Retrieve audit record from database.
    
    Args:
        audit_id: The audit ID to retrieve
        
    Returns:
        Audit model instance or None
    """
    try:
        from models import get_db, Audit
        db = get_db()
        if not db:
            logger.warning("Database unavailable for audit retrieval")
            return None
        
        audit = db.query(Audit).filter(Audit.id == audit_id).first()
        db.close()
        return audit
    except Exception as e:
        logger.error(f"Error retrieving audit {audit_id} from DB: {e}")
        return None


def rebuild_audit_data_from_db(audit_id: int) -> Optional[Dict[str, Any]]:
    """
    Rebuild complete audit_data dictionary from database record.
    
    This is the fallback when session cache is missing.
    Auto-heals missing fields to prevent PDF/display breakage.
    
    Args:
        audit_id: The audit ID to rebuild
        
    Returns:
        Complete audit_data dictionary or None if not found
    """
    audit = get_audit_from_db(audit_id)
    if not audit:
        logger.warning(f"Could not rebuild audit {audit_id} - not found in DB")
        return None
    
    try:
        # Parse JSON fields
        issues = []
        if audit.issues:
            try:
                issues = json.loads(audit.issues) if isinstance(audit.issues, str) else audit.issues
            except json.JSONDecodeError:
                issues = []
        
        tech_stack = []
        if audit.tech_stack:
            try:
                tech_stack = json.loads(audit.tech_stack) if isinstance(audit.tech_stack, str) else audit.tech_stack
            except json.JSONDecodeError:
                tech_stack = []
        
        ai_data = {'summary': '', 'impact': '', 'solutions': '', 'email': ''}
        if audit.ai_analysis:
            try:
                ai_data = json.loads(audit.ai_analysis) if isinstance(audit.ai_analysis, str) else audit.ai_analysis
            except json.JSONDecodeError:
                pass
        
        # Build complete audit_data dictionary
        audit_data = {
            'url': f"https://{audit.domain}" if audit.domain else '',
            'domain': audit.domain or '',
            'score': audit.health_score or 0,
            'psi': audit.speed_score or 'N/A',
            'domain_age': audit.domain_age or 'Unknown',
            'tech_stack': tech_stack,
            'issues': issues,
            'raw_html': audit.raw_html or '',
            'ai': {
                'summary': ai_data.get('summary', 'No summary available'),
                'impact': ai_data.get('impact', 'No impact assessment available'),
                'solutions': ai_data.get('solutions', 'No solutions available'),
                'email': ai_data.get('email', 'No email draft available')
            },
            'audit_id': audit.id,
            'created_at': audit.created_at.isoformat() if audit.created_at else None,
            'username': getattr(audit, 'username', None),
            'source': getattr(audit, 'source', 'single')
        }
        
        # Auto-heal any missing fields
        audit_data = _ensure_audit_fields(audit_data)
        
        logger.info(f"Rebuilt audit data from DB for audit {audit_id}")
        return audit_data
        
    except Exception as e:
        logger.error(f"Error rebuilding audit {audit_id} from DB: {e}")
        return None


def persist_audit_data(audit_id: int, audit_data: Dict[str, Any]) -> bool:
    """
    Persist audit data to all storage layers.
    
    Saves to:
    1. Session state (memory)
    2. Disk cache (JSON file)
    
    The database is already updated by save_audit_to_db().
    
    Args:
        audit_id: The audit ID
        audit_data: Complete audit data dictionary
        
    Returns:
        True if persistence succeeded
    """
    if not audit_id or not audit_data:
        logger.warning("persist_audit_data called with empty audit_id or data")
        return False
    
    try:
        # Ensure all fields exist
        audit_data = _ensure_audit_fields(audit_data)
        audit_data['audit_id'] = audit_id
        
        # 1. Save to session state
        if '_audit_cache' not in st.session_state:
            st.session_state._audit_cache = {}
        
        st.session_state._audit_cache[str(audit_id)] = audit_data
        
        # 2. Save to disk cache
        domain = _sanitize_domain(audit_data.get('domain', ''))
        if domain:
            cache = _load_audit_cache()
            
            # Store by both audit_id and domain for flexible lookup
            cache[str(audit_id)] = {
                'audit_id': audit_id,
                'domain': domain,
                'data': audit_data,
                'cached_at': datetime.now().isoformat()
            }
            
            # Also index by domain for quick lookup
            cache[f"domain:{domain}"] = {
                'audit_id': audit_id,
                'latest': True
            }
            
            _save_audit_cache(cache)
        
        logger.debug(f"Persisted audit data for audit {audit_id}")
        return True
        
    except Exception as e:
        logger.error(f"Error persisting audit data: {e}")
        return False


def load_audit_data(audit_id: int) -> Optional[Dict[str, Any]]:
    """
    Load audit data with fallback chain.
    
    Priority:
    1. Session state cache (fastest)
    2. Disk cache (survives refresh)
    3. Database rebuild (survives logout)
    
    Args:
        audit_id: The audit ID to load
        
    Returns:
        Complete audit_data dictionary or None
    """
    if not audit_id:
        return None
    
    str_id = str(audit_id)
    
    # 1. Try session state cache
    if '_audit_cache' in st.session_state:
        if str_id in st.session_state._audit_cache:
            logger.debug(f"Loaded audit {audit_id} from session cache")
            return _ensure_audit_fields(st.session_state._audit_cache[str_id])
    
    # 2. Try disk cache
    cache = _load_audit_cache()
    if str_id in cache:
        cached = cache[str_id]
        audit_data = cached.get('data')
        if audit_data:
            # Restore to session cache
            if '_audit_cache' not in st.session_state:
                st.session_state._audit_cache = {}
            st.session_state._audit_cache[str_id] = audit_data
            logger.debug(f"Loaded audit {audit_id} from disk cache")
            return _ensure_audit_fields(audit_data)
    
    # 3. Rebuild from database
    audit_data = rebuild_audit_data_from_db(audit_id)
    if audit_data:
        # Persist to caches for future lookups
        persist_audit_data(audit_id, audit_data)
        return audit_data
    
    logger.warning(f"Could not load audit {audit_id} from any source")
    return None


def get_current_audit() -> Optional[Dict[str, Any]]:
    """
    Get the currently selected audit data.
    
    Returns the full audit_data dictionary for the current audit,
    loading from cache/DB if necessary.
    
    Returns:
        Complete audit_data dictionary or None
    """
    # Check for current audit ID
    current_id = st.session_state.get('_current_audit_id')
    
    if current_id:
        return load_audit_data(current_id)
    
    # Legacy fallback: check old session state key
    legacy_data = st.session_state.get('current_audit_data')
    if legacy_data:
        # Migrate to new system
        audit_id = legacy_data.get('audit_id')
        if audit_id:
            persist_audit_data(audit_id, legacy_data)
            st.session_state._current_audit_id = audit_id
            return _ensure_audit_fields(legacy_data)
        return _ensure_audit_fields(legacy_data)
    
    return None


def set_current_audit(audit_id: int) -> bool:
    """
    Set the current audit by ID.
    
    This loads the audit data and sets it as the current selection.
    
    Args:
        audit_id: The audit ID to set as current
        
    Returns:
        True if audit was found and set
    """
    if not audit_id:
        return False
    
    audit_data = load_audit_data(audit_id)
    if audit_data:
        st.session_state._current_audit_id = audit_id
        # Also set legacy key for backward compatibility
        st.session_state.current_audit_data = audit_data
        logger.debug(f"Set current audit to {audit_id}")
        return True
    
    logger.warning(f"Could not set current audit - audit {audit_id} not found")
    return False


def clear_current_audit():
    """
    Clear the current audit selection.
    
    This does NOT delete the audit from cache/DB, just clears the selection.
    """
    st.session_state.pop('_current_audit_id', None)
    st.session_state.pop('current_audit_data', None)
    logger.debug("Cleared current audit selection")


def get_audit_by_domain(domain: str) -> Optional[Dict[str, Any]]:
    """
    Get the most recent audit for a domain.
    
    Args:
        domain: The domain to look up
        
    Returns:
        Complete audit_data dictionary or None
    """
    domain = _sanitize_domain(domain)
    if not domain:
        return None
    
    # Check disk cache for domain index
    cache = _load_audit_cache()
    domain_key = f"domain:{domain}"
    
    if domain_key in cache:
        audit_id = cache[domain_key].get('audit_id')
        if audit_id:
            return load_audit_data(audit_id)
    
    # Fallback: Query database for latest audit of this domain
    try:
        from models import get_db, Audit
        db = get_db()
        if db:
            audit = db.query(Audit).filter(
                Audit.domain == domain
            ).order_by(Audit.created_at.desc()).first()
            db.close()
            
            if audit:
                return load_audit_data(audit.id)
    except Exception as e:
        logger.error(f"Error looking up audit for domain {domain}: {e}")
    
    return None
