"""
Navigation State Persistence Module
====================================

Tracks user navigation and ensures the correct section/audit
is restored after refresh, tab switch, or logout.

This module handles:
- Deep link restoration (URL params → session state)
- Section persistence (remembers where user was)
- Audit context preservation during navigation
- Query param synchronization

Functions:
----------
- save_navigation_state(section_name, audit_id): Save current location
- load_navigation_state(): Load saved location
- clear_navigation_state(): Clear saved location
- get_deep_link_audit_id(): Extract audit ID from URL
- sync_query_params(): Synchronize URL params with session

Author: Code Nest LLC
"""

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

import streamlit as st

# Thread lock for file operations
_file_lock = threading.Lock()

# Cache directory and file
CACHE_DIR = Path(__file__).parent.parent / ".cache"
NAV_STATE_FILE = CACHE_DIR / "navigation_state.json"

# Ensure cache directory exists
CACHE_DIR.mkdir(exist_ok=True)

# Logger
logger = logging.getLogger("sales_engine.persistence.navigation")

# Valid section names for navigation
VALID_SECTIONS = {
    "Single Audit",
    "Bulk Audit", 
    "Email Outreach",
    "Lead CRM",
    "Call Log",
    "Settings",
    "Analysis Dashboard"
}


def _load_nav_cache() -> Dict[str, Any]:
    """Load navigation state cache from disk."""
    with _file_lock:
        try:
            if NAV_STATE_FILE.exists():
                return json.loads(NAV_STATE_FILE.read_text())
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load navigation cache: {e}")
        return {}


def _save_nav_cache(cache: Dict[str, Any]) -> bool:
    """Save navigation state cache to disk."""
    with _file_lock:
        try:
            NAV_STATE_FILE.write_text(json.dumps(cache, indent=2, default=str))
            return True
        except IOError as e:
            logger.error(f"Failed to save navigation cache: {e}")
            return False


def _get_user_key() -> str:
    """
    Get a unique key for the current user.
    
    Uses username if logged in, otherwise 'anonymous'.
    """
    username = st.session_state.get('username', 'anonymous')
    return f"user_{username}"


def save_navigation_state(section_name: str, audit_id: Optional[int] = None) -> bool:
    """
    Save the current navigation state.
    
    This should be called whenever the user navigates to a new section
    or opens an audit.
    
    Args:
        section_name: Name of the section (e.g., "Single Audit", "Bulk Audit")
        audit_id: Optional audit ID if viewing a specific audit
        
    Returns:
        True if state was saved successfully
    """
    if section_name not in VALID_SECTIONS:
        logger.warning(f"Invalid section name: {section_name}")
        # Still save it but log warning
    
    user_key = _get_user_key()
    
    nav_state = {
        'section': section_name,
        'audit_id': audit_id,
        'timestamp': datetime.now().isoformat()
    }
    
    # 1. Save to session state
    st.session_state._nav_state = nav_state
    
    # 2. Save to disk cache
    cache = _load_nav_cache()
    cache[user_key] = nav_state
    success = _save_nav_cache(cache)
    
    logger.debug(f"Saved navigation state: {section_name}, audit_id={audit_id}")
    return success


def load_navigation_state() -> Tuple[Optional[str], Optional[int]]:
    """
    Load the saved navigation state.
    
    Uses fallback chain:
    1. Session state
    2. Disk cache
    
    Returns:
        Tuple of (section_name, audit_id) or (None, None) if not found
    """
    user_key = _get_user_key()
    
    # 1. Try session state
    if '_nav_state' in st.session_state:
        nav = st.session_state._nav_state
        return (nav.get('section'), nav.get('audit_id'))
    
    # 2. Try disk cache
    cache = _load_nav_cache()
    if user_key in cache:
        nav = cache[user_key]
        # Restore to session
        st.session_state._nav_state = nav
        logger.debug(f"Restored navigation state from disk: {nav}")
        return (nav.get('section'), nav.get('audit_id'))
    
    return (None, None)


def clear_navigation_state() -> bool:
    """
    Clear the saved navigation state.
    
    Call this on logout or when resetting the app.
    
    Returns:
        True if state was cleared
    """
    user_key = _get_user_key()
    
    # Clear from session
    if '_nav_state' in st.session_state:
        del st.session_state._nav_state
    
    # Clear from disk
    cache = _load_nav_cache()
    if user_key in cache:
        del cache[user_key]
        _save_nav_cache(cache)
    
    logger.debug("Cleared navigation state")
    return True


def get_deep_link_audit_id() -> Optional[int]:
    """
    Extract audit ID from URL query parameters.
    
    This allows deep linking to specific audits via URL:
    ?audit_id=123
    
    Returns:
        Audit ID from URL, or None if not present
    """
    try:
        query_params = st.query_params
        audit_id_str = query_params.get('audit_id', None)
        
        if audit_id_str:
            audit_id = int(audit_id_str)
            logger.debug(f"Found deep link audit_id: {audit_id}")
            return audit_id
    except (ValueError, TypeError) as e:
        logger.warning(f"Invalid audit_id in URL: {e}")
    except Exception as e:
        logger.error(f"Error reading query params: {e}")
    
    return None


def set_deep_link_audit_id(audit_id: int) -> bool:
    """
    Set the audit ID in URL query parameters.
    
    This creates a shareable deep link to a specific audit.
    
    Args:
        audit_id: The audit ID to set in URL
        
    Returns:
        True if successful
    """
    try:
        st.query_params['audit_id'] = str(audit_id)
        logger.debug(f"Set deep link audit_id: {audit_id}")
        return True
    except Exception as e:
        logger.error(f"Error setting query params: {e}")
        return False


def clear_deep_link() -> bool:
    """
    Clear the audit ID from URL query parameters.
    
    Returns:
        True if successful
    """
    try:
        if 'audit_id' in st.query_params:
            del st.query_params['audit_id']
        return True
    except Exception as e:
        logger.error(f"Error clearing query params: {e}")
        return False


def sync_query_params() -> Optional[int]:
    """
    Synchronize URL query parameters with session state.
    
    This should be called early in app initialization.
    
    Priority:
    1. If URL has audit_id, use it and update session
    2. If session has audit_id but URL doesn't, update URL
    3. If neither has audit_id, return None
    
    Returns:
        The synchronized audit ID, or None
    """
    url_audit_id = get_deep_link_audit_id()
    session_audit_id = st.session_state.get('_current_audit_id')
    
    if url_audit_id:
        # URL takes precedence - update session
        if url_audit_id != session_audit_id:
            st.session_state._current_audit_id = url_audit_id
            logger.info(f"Synced audit_id from URL: {url_audit_id}")
        return url_audit_id
    
    elif session_audit_id:
        # Session has value, sync to URL
        set_deep_link_audit_id(session_audit_id)
        return session_audit_id
    
    return None


def restore_navigation_on_refresh() -> Dict[str, Any]:
    """
    Comprehensive navigation restoration on page refresh.
    
    This should be called once at app startup. It:
    1. Checks for deep link audit ID
    2. Loads saved navigation state
    3. Loads the audit data if applicable
    4. Returns restoration status
    
    Returns:
        Dict with restoration status and details
    """
    result = {
        'restored': False,
        'section': None,
        'audit_id': None,
        'source': None
    }
    
    # 1. Check for deep link
    deep_link_id = sync_query_params()
    if deep_link_id:
        result['audit_id'] = deep_link_id
        result['source'] = 'deep_link'
        
        # Load the audit data
        try:
            from .audit_state import set_current_audit
            set_current_audit(deep_link_id)
            result['restored'] = True
            logger.info(f"Restored from deep link: audit {deep_link_id}")
        except Exception as e:
            logger.error(f"Failed to restore audit from deep link: {e}")
    
    # 2. Load navigation state
    section, audit_id = load_navigation_state()
    if section:
        result['section'] = section
        if not result['audit_id'] and audit_id:
            result['audit_id'] = audit_id
            result['source'] = 'nav_state'
        result['restored'] = True
    
    return result


def get_section_for_audit(audit_id: int) -> str:
    """
    Determine the appropriate section for an audit.
    
    Uses navigation state or defaults based on audit source.
    
    Args:
        audit_id: The audit ID
        
    Returns:
        Section name (defaults to "Single Audit")
    """
    section, nav_audit_id = load_navigation_state()
    
    if nav_audit_id == audit_id and section:
        return section
    
    return "Single Audit"
