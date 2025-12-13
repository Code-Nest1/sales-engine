"""
PDF Context Persistence Module
==============================

Ensures PDF generation works even after page refresh by
maintaining a persistent context of audit data.

The PDF generator needs the full audit_data dictionary.
This module guarantees that data is available by:
1. Storing context when audit completes
2. Rebuilding from cache/DB if session lost
3. Auto-filling empty fields to prevent breakage

Functions:
----------
- store_pdf_context(audit_id, audit_data): Store context for PDF generation
- load_pdf_context(audit_id): Load context, rebuilding if necessary
- clear_pdf_context(audit_id): Clear stored context

Author: Code Nest LLC
"""

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

import streamlit as st

# Thread lock for file operations
_file_lock = threading.Lock()

# Cache directory and file
CACHE_DIR = Path(__file__).parent.parent / ".cache"
PDF_CONTEXT_FILE = CACHE_DIR / "pdf_context.json"

# Ensure cache directory exists
CACHE_DIR.mkdir(exist_ok=True)

# Logger
logger = logging.getLogger("sales_engine.persistence.pdf_context")


def _load_pdf_cache() -> Dict[str, Any]:
    """Load PDF context cache from disk with thread safety."""
    with _file_lock:
        try:
            if PDF_CONTEXT_FILE.exists():
                return json.loads(PDF_CONTEXT_FILE.read_text())
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load PDF context cache: {e}")
        return {}


def _save_pdf_cache(cache: Dict[str, Any]) -> bool:
    """Save PDF context cache to disk with thread safety."""
    with _file_lock:
        try:
            PDF_CONTEXT_FILE.write_text(json.dumps(cache, indent=2, default=str))
            return True
        except IOError as e:
            logger.error(f"Failed to save PDF context cache: {e}")
            return False


def _get_default_pdf_context() -> Dict[str, Any]:
    """
    Return a default PDF context with all fields required by the PDF generator.
    
    This ensures the PDF never breaks due to missing fields.
    """
    return {
        'url': '',
        'domain': 'Unknown Domain',
        'score': 0,
        'psi': 'N/A',
        'domain_age': 'Unknown',
        'tech_stack': [],
        'issues': [],
        'ai': {
            'summary': 'No summary available',
            'impact': 'No impact assessment available',
            'solutions': 'No solutions available',
            'email': 'No email draft available'
        },
        'audit_id': None,
        'created_at': datetime.now().isoformat(),
        'generated_at': datetime.now().isoformat()
    }


def _ensure_pdf_fields(audit_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure all required PDF fields exist in audit data.
    
    This auto-heals missing fields to prevent PDF generation failures.
    """
    if not audit_data:
        return _get_default_pdf_context()
    
    defaults = _get_default_pdf_context()
    result = audit_data.copy()
    
    # Merge with defaults (keep existing values, add missing)
    for key, value in defaults.items():
        if key not in result or result[key] is None:
            result[key] = value
        elif key == 'ai':
            # Ensure AI sub-fields exist
            if not isinstance(result.get('ai'), dict):
                result['ai'] = defaults['ai']
            else:
                for ai_key, ai_value in defaults['ai'].items():
                    if ai_key not in result['ai'] or not result['ai'][ai_key]:
                        result['ai'][ai_key] = ai_value
    
    # Ensure lists are actually lists
    if not isinstance(result.get('tech_stack'), list):
        result['tech_stack'] = []
    if not isinstance(result.get('issues'), list):
        result['issues'] = []
    
    return result


def store_pdf_context(audit_id: int, audit_data: Dict[str, Any]) -> bool:
    """
    Store audit data context for PDF generation.
    
    This should be called after every successful audit to ensure
    PDF generation works even after page refresh.
    
    Args:
        audit_id: The audit ID
        audit_data: Complete audit data dictionary
        
    Returns:
        True if context was stored successfully
    """
    if not audit_id:
        logger.warning("store_pdf_context called with empty audit_id")
        return False
    
    # Ensure all fields exist
    audit_data = _ensure_pdf_fields(audit_data or {})
    audit_data['audit_id'] = audit_id
    audit_data['stored_at'] = datetime.now().isoformat()
    
    str_id = str(audit_id)
    
    # 1. Store in session state
    if '_pdf_context' not in st.session_state:
        st.session_state._pdf_context = {}
    st.session_state._pdf_context[str_id] = audit_data
    
    # 2. Store on disk
    cache = _load_pdf_cache()
    cache[str_id] = audit_data
    
    # Limit cache size (keep last 100 contexts)
    if len(cache) > 100:
        # Remove oldest entries
        sorted_keys = sorted(
            cache.keys(),
            key=lambda k: cache[k].get('stored_at', ''),
            reverse=True
        )
        cache = {k: cache[k] for k in sorted_keys[:100]}
    
    success = _save_pdf_cache(cache)
    
    if success:
        logger.debug(f"Stored PDF context for audit {audit_id}")
    
    return success


def load_pdf_context(audit_id: int) -> Optional[Dict[str, Any]]:
    """
    Load PDF context for an audit.
    
    Uses a fallback chain:
    1. Session state (fastest)
    2. Disk cache (survives refresh)
    3. Rebuild from audit_state (survives logout)
    
    Always returns a valid context with all fields populated.
    
    Args:
        audit_id: The audit ID
        
    Returns:
        Complete audit data suitable for PDF generation
    """
    if not audit_id:
        logger.warning("load_pdf_context called with empty audit_id")
        return _get_default_pdf_context()
    
    str_id = str(audit_id)
    
    # 1. Try session state
    if '_pdf_context' in st.session_state:
        if str_id in st.session_state._pdf_context:
            logger.debug(f"PDF context hit (session) for audit {audit_id}")
            return _ensure_pdf_fields(st.session_state._pdf_context[str_id])
    
    # 2. Try disk cache
    cache = _load_pdf_cache()
    if str_id in cache:
        context = cache[str_id]
        # Restore to session
        if '_pdf_context' not in st.session_state:
            st.session_state._pdf_context = {}
        st.session_state._pdf_context[str_id] = context
        logger.debug(f"PDF context hit (disk) for audit {audit_id}")
        return _ensure_pdf_fields(context)
    
    # 3. Rebuild from audit_state module
    try:
        from .audit_state import load_audit_data
        audit_data = load_audit_data(audit_id)
        if audit_data:
            # Store for future use
            store_pdf_context(audit_id, audit_data)
            logger.info(f"Rebuilt PDF context from audit_state for audit {audit_id}")
            return _ensure_pdf_fields(audit_data)
    except ImportError as e:
        logger.error(f"Could not import audit_state: {e}")
    except Exception as e:
        logger.error(f"Error rebuilding PDF context: {e}")
    
    # 4. Return default context as last resort
    logger.warning(f"Could not load PDF context for audit {audit_id}, using defaults")
    return _get_default_pdf_context()


def clear_pdf_context(audit_id: int) -> bool:
    """
    Clear stored PDF context for an audit.
    
    Args:
        audit_id: The audit ID to clear
        
    Returns:
        True if context was cleared
    """
    if not audit_id:
        return False
    
    str_id = str(audit_id)
    
    # Clear from session state
    if '_pdf_context' in st.session_state:
        st.session_state._pdf_context.pop(str_id, None)
    
    # Clear from disk cache
    cache = _load_pdf_cache()
    if str_id in cache:
        del cache[str_id]
        _save_pdf_cache(cache)
    
    logger.debug(f"Cleared PDF context for audit {audit_id}")
    return True


def get_pdf_context_or_current() -> Dict[str, Any]:
    """
    Get PDF context for the current audit, or create one.
    
    This is a convenience function that:
    1. Gets the current audit ID from session
    2. Loads the PDF context for it
    3. Falls back to session_state.current_audit_data if available
    4. Returns default context if all else fails
    
    Returns:
        Complete audit data suitable for PDF generation
    """
    # Try current audit ID
    current_id = st.session_state.get('_current_audit_id')
    if current_id:
        context = load_pdf_context(current_id)
        if context:
            return context
    
    # Try legacy current_audit_data
    legacy_data = st.session_state.get('current_audit_data')
    if legacy_data:
        audit_id = legacy_data.get('audit_id')
        if audit_id:
            store_pdf_context(audit_id, legacy_data)
        return _ensure_pdf_fields(legacy_data)
    
    return _get_default_pdf_context()
