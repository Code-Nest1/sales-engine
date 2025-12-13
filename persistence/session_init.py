"""
Session Initialization Module
==============================

Provides a single initialization function that sets up all
persistence layers and restores state on app startup.

This module should be called once at the top of app.py
to ensure all persistence is properly initialized.

Functions:
----------
- init_app_session_persistence(): Initialize all persistence layers

Author: Code Nest LLC
"""

import logging
from typing import Dict, Any

import streamlit as st

# Logger
logger = logging.getLogger("sales_engine.persistence.session_init")


def init_app_session_persistence() -> Dict[str, Any]:
    """
    Initialize all persistence layers for the application.
    
    This should be called ONCE at the top of app.py, after
    Streamlit page config but before any other code.
    
    What it does:
    1. Ensures cache directory exists
    2. Initializes session state containers
    3. Restores navigation state from last session
    4. Syncs URL query params with session
    5. Loads cached audit data if available
    6. Returns initialization status
    
    Returns:
        Dict with initialization status and restored data info
    """
    result = {
        'initialized': False,
        'restored_audit': None,
        'restored_section': None,
        'ai_cache_loaded': False,
        'errors': []
    }
    
    # Skip if already initialized this session
    if st.session_state.get('_persistence_initialized'):
        return {
            'initialized': True,
            'skipped': True,
            'restored_audit': st.session_state.get('_current_audit_id'),
            'restored_section': st.session_state.get('_nav_state', {}).get('section'),
            'errors': []
        }
    
    logger.info("Initializing app session persistence...")
    
    # 1. Ensure cache directory exists
    try:
        from pathlib import Path
        cache_dir = Path(__file__).parent.parent / ".cache"
        cache_dir.mkdir(exist_ok=True)
        logger.debug(f"Cache directory ready: {cache_dir}")
    except Exception as e:
        error_msg = f"Failed to create cache directory: {e}"
        logger.error(error_msg)
        result['errors'].append(error_msg)
    
    # 2. Initialize session state containers
    _init_session_containers()
    
    # 3. Restore navigation state
    try:
        from .navigation_state import restore_navigation_on_refresh
        nav_result = restore_navigation_on_refresh()
        if nav_result.get('restored'):
            result['restored_section'] = nav_result.get('section')
            result['restored_audit'] = nav_result.get('audit_id')
            logger.info(f"Navigation restored: section={result['restored_section']}, "
                       f"audit={result['restored_audit']}")
    except Exception as e:
        error_msg = f"Failed to restore navigation: {e}"
        logger.error(error_msg)
        result['errors'].append(error_msg)
    
    # 4. Restore current audit data
    if result['restored_audit']:
        try:
            from .audit_state import load_audit_data
            audit_data = load_audit_data(result['restored_audit'])
            if audit_data:
                # Also populate legacy session state for compatibility
                st.session_state.current_audit_data = audit_data
                logger.info(f"Audit data loaded for audit {result['restored_audit']}")
        except Exception as e:
            error_msg = f"Failed to load audit data: {e}"
            logger.error(error_msg)
            result['errors'].append(error_msg)
    
    # 5. Preload AI cache index for faster lookups
    try:
        from .ai_cache import _load_ai_cache
        ai_cache = _load_ai_cache()
        result['ai_cache_loaded'] = len(ai_cache) > 0
        if result['ai_cache_loaded']:
            logger.debug(f"AI cache loaded with {len(ai_cache)} entries")
    except Exception as e:
        # Non-critical error
        logger.warning(f"AI cache preload failed: {e}")
    
    # 6. Mark as initialized
    st.session_state._persistence_initialized = True
    result['initialized'] = True
    
    logger.info("Session persistence initialization complete")
    return result


def _init_session_containers() -> None:
    """
    Initialize all session state containers used by persistence layer.
    
    This ensures all required session keys exist with proper defaults.
    """
    # Audit state containers
    if '_audit_cache' not in st.session_state:
        st.session_state._audit_cache = {}
    
    if '_current_audit_id' not in st.session_state:
        st.session_state._current_audit_id = None
    
    # AI cache containers
    if '_ai_cache' not in st.session_state:
        st.session_state._ai_cache = {}
    
    if '_regen_counts' not in st.session_state:
        st.session_state._regen_counts = {}
    
    # PDF context container
    if '_pdf_context' not in st.session_state:
        st.session_state._pdf_context = {}
    
    # Navigation state container
    if '_nav_state' not in st.session_state:
        st.session_state._nav_state = {}
    
    # Legacy compatibility - ensure these exist
    if 'current_audit_data' not in st.session_state:
        st.session_state.current_audit_data = None
    
    logger.debug("Session containers initialized")


def reset_persistence_state() -> bool:
    """
    Reset all persistence state (useful for logout or hard reset).
    
    This clears:
    - Audit cache containers
    - Current audit selection
    - Navigation state
    - AI cache containers
    - PDF context containers
    
    Does NOT clear (CRITICAL):
    - API keys (OPENAI_API_KEY, GOOGLE_API_KEY, SLACK_WEBHOOK)
    - SMTP settings (_smtp_host, _smtp_port, _smtp_user, _smtp_pass)
    - Disk caches (audit_cache.json, ai_cache.json, etc.)
    - Database records
    
    Returns:
        True if reset was successful
    """
    try:
        # Clear session containers - but NOT API keys or SMTP settings
        st.session_state._audit_cache = {}
        st.session_state._current_audit_id = None
        st.session_state._ai_cache = {}
        st.session_state._regen_counts = {}
        st.session_state._pdf_context = {}
        st.session_state._nav_state = {}
        st.session_state.current_audit_data = None
        
        # Reset initialization flag
        st.session_state._persistence_initialized = False
        
        # Clear navigation state on disk
        try:
            from .navigation_state import clear_navigation_state
            clear_navigation_state()
        except Exception:
            pass
        
        # IMPORTANT: Do NOT clear these keys:
        # - OPENAI_API_KEY, GOOGLE_API_KEY, SLACK_WEBHOOK
        # - _smtp_host, _smtp_port, _smtp_user, _smtp_pass
        
        logger.info("Persistence state reset (API keys preserved)")
        return True
        
    except Exception as e:
        logger.error(f"Failed to reset persistence state: {e}")
        return False


def get_persistence_status() -> Dict[str, Any]:
    """
    Get current status of all persistence layers.
    
    Useful for debugging and status display.
    
    Returns:
        Dict with status of each persistence component
    """
    from pathlib import Path
    
    cache_dir = Path(__file__).parent.parent / ".cache"
    
    status = {
        'initialized': st.session_state.get('_persistence_initialized', False),
        'cache_dir_exists': cache_dir.exists(),
        'current_audit_id': st.session_state.get('_current_audit_id'),
        'audit_cache_count': len(st.session_state.get('_audit_cache', {})),
        'ai_cache_count': len(st.session_state.get('_ai_cache', {})),
        'pdf_context_count': len(st.session_state.get('_pdf_context', {})),
        'nav_state': st.session_state.get('_nav_state', {}),
    }
    
    # Check disk cache files
    disk_caches = ['audit_cache.json', 'ai_cache.json', 'regeneration.json', 
                   'pdf_context.json', 'navigation_state.json']
    status['disk_caches'] = {}
    for cache_file in disk_caches:
        path = cache_dir / cache_file
        status['disk_caches'][cache_file] = {
            'exists': path.exists(),
            'size': path.stat().st_size if path.exists() else 0
        }
    
    return status


def on_logout_cleanup() -> None:
    """
    Cleanup function to call when user logs out.
    
    This preserves disk caches but clears session state,
    so a different user logging in gets a fresh session.
    """
    try:
        from .navigation_state import clear_navigation_state
        clear_navigation_state()
    except Exception:
        pass
    
    # Reset session containers
    reset_persistence_state()
    logger.info("Logout cleanup complete")
