"""
AI Cache Persistence Module
===========================

Caches AI analysis results to prevent costly recomputation.
Also tracks regeneration counts to enforce limits.

Features:
- Domain-keyed caching
- 7-day expiration
- Regeneration limit enforcement (default: 5)
- Thread-safe file operations

Functions:
----------
- get_ai_cache(domain): Get cached AI analysis
- save_ai_cache(domain, ai_data): Cache AI analysis
- ai_cache_exists(domain): Check if cache exists and is valid
- clear_ai_cache(domain): Clear cache for domain
- get_regen_count(domain): Get regeneration count
- increment_regen_count(domain): Increment counter
- reset_regen_count(domain): Reset counter
- regen_limit_reached(domain): Check if limit reached

Author: Code Nest LLC
"""

import json
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import streamlit as st

# Thread lock for file operations
_file_lock = threading.Lock()

# Cache directory and files
CACHE_DIR = Path(__file__).parent.parent / ".cache"
AI_CACHE_FILE = CACHE_DIR / "ai_cache.json"
REGEN_CACHE_FILE = CACHE_DIR / "regeneration.json"

# Ensure cache directory exists
CACHE_DIR.mkdir(exist_ok=True)

# Configuration
AI_CACHE_EXPIRY_DAYS = 7
REGEN_LIMIT = 5

# Logger
logger = logging.getLogger("sales_engine.persistence.ai_cache")


def _sanitize_domain(domain: str) -> str:
    """Sanitize domain name for use as cache key."""
    if not domain:
        return ""
    domain = domain.lower().strip()
    if domain.startswith(('http://', 'https://')):
        try:
            domain = urlparse(domain).netloc
        except Exception:
            pass
    domain = domain.replace('www.', '')
    domain = ''.join(c for c in domain if c.isalnum() or c in '.-_')
    return domain[:100]


def _load_ai_cache() -> Dict[str, Any]:
    """Load AI cache from disk with thread safety."""
    with _file_lock:
        try:
            if AI_CACHE_FILE.exists():
                return json.loads(AI_CACHE_FILE.read_text())
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load AI cache: {e}")
        return {}


def _save_ai_cache(cache: Dict[str, Any]) -> bool:
    """Save AI cache to disk with thread safety."""
    with _file_lock:
        try:
            AI_CACHE_FILE.write_text(json.dumps(cache, indent=2, default=str))
            return True
        except IOError as e:
            logger.error(f"Failed to save AI cache: {e}")
            return False


def _load_regen_cache() -> Dict[str, Any]:
    """Load regeneration cache from disk with thread safety."""
    with _file_lock:
        try:
            if REGEN_CACHE_FILE.exists():
                return json.loads(REGEN_CACHE_FILE.read_text())
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load regen cache: {e}")
        return {}


def _save_regen_cache(cache: Dict[str, Any]) -> bool:
    """Save regeneration cache to disk with thread safety."""
    with _file_lock:
        try:
            REGEN_CACHE_FILE.write_text(json.dumps(cache, indent=2, default=str))
            return True
        except IOError as e:
            logger.error(f"Failed to save regen cache: {e}")
            return False


def _is_cache_expired(cached_at: str) -> bool:
    """Check if cache entry has expired."""
    try:
        cached_time = datetime.fromisoformat(cached_at)
        expiry_time = cached_time + timedelta(days=AI_CACHE_EXPIRY_DAYS)
        return datetime.now() > expiry_time
    except (ValueError, TypeError):
        return True


def _get_default_ai_data() -> Dict[str, str]:
    """Return default AI analysis structure."""
    return {
        'summary': 'No summary available',
        'impact': 'No impact assessment available',
        'solutions': 'No solutions available',
        'email': 'No email draft available'
    }


# ============================================================================
# AI CACHE FUNCTIONS
# ============================================================================

def get_ai_cache(domain: str) -> Optional[Dict[str, str]]:
    """
    Get cached AI analysis for a domain.
    
    Args:
        domain: The domain to look up
        
    Returns:
        AI analysis dict (summary, impact, solutions, email) or None if not cached/expired
    """
    domain = _sanitize_domain(domain)
    if not domain:
        return None
    
    # 1. Check session state first (fastest)
    session_key = f"_ai_cache_{domain}"
    if session_key in st.session_state:
        cached = st.session_state[session_key]
        if not _is_cache_expired(cached.get('cached_at', '')):
            logger.debug(f"AI cache hit (session) for {domain}")
            return cached.get('data')
    
    # 2. Check disk cache
    cache = _load_ai_cache()
    if domain in cache:
        cached = cache[domain]
        if not _is_cache_expired(cached.get('cached_at', '')):
            # Restore to session cache
            st.session_state[session_key] = cached
            logger.debug(f"AI cache hit (disk) for {domain}")
            return cached.get('data')
        else:
            # Expired - remove from cache
            del cache[domain]
            _save_ai_cache(cache)
            logger.debug(f"AI cache expired for {domain}")
    
    return None


def save_ai_cache(domain: str, ai_data: Dict[str, str]) -> bool:
    """
    Cache AI analysis for a domain.
    
    Args:
        domain: The domain to cache
        ai_data: AI analysis dict with summary, impact, solutions, email
        
    Returns:
        True if cache was saved successfully
    """
    domain = _sanitize_domain(domain)
    if not domain or not ai_data:
        return False
    
    # Validate ai_data has required fields
    defaults = _get_default_ai_data()
    for key in defaults:
        if key not in ai_data:
            ai_data[key] = defaults[key]
    
    cache_entry = {
        'data': ai_data,
        'cached_at': datetime.now().isoformat(),
        'domain': domain
    }
    
    # 1. Save to session state
    session_key = f"_ai_cache_{domain}"
    st.session_state[session_key] = cache_entry
    
    # 2. Save to disk cache
    cache = _load_ai_cache()
    cache[domain] = cache_entry
    success = _save_ai_cache(cache)
    
    if success:
        logger.info(f"Saved AI cache for {domain}")
    
    return success


def ai_cache_exists(domain: str) -> bool:
    """
    Check if valid (non-expired) AI cache exists for domain.
    
    Args:
        domain: The domain to check
        
    Returns:
        True if valid cache exists
    """
    return get_ai_cache(domain) is not None


def clear_ai_cache(domain: str) -> bool:
    """
    Clear AI cache for a specific domain.
    
    Args:
        domain: The domain to clear
        
    Returns:
        True if cache was cleared
    """
    domain = _sanitize_domain(domain)
    if not domain:
        return False
    
    # Clear from session state
    session_key = f"_ai_cache_{domain}"
    st.session_state.pop(session_key, None)
    
    # Clear from disk cache
    cache = _load_ai_cache()
    if domain in cache:
        del cache[domain]
        _save_ai_cache(cache)
    
    logger.info(f"Cleared AI cache for {domain}")
    return True


# ============================================================================
# REGENERATION TRACKING FUNCTIONS
# ============================================================================

def get_regen_count(domain: str) -> int:
    """
    Get the regeneration count for a domain.
    
    Args:
        domain: The domain to check
        
    Returns:
        Current regeneration count (0 if not tracked)
    """
    domain = _sanitize_domain(domain)
    if not domain:
        return 0
    
    # 1. Check session state first
    session_key = f"_regen_count_{domain}"
    if session_key in st.session_state:
        return st.session_state[session_key]
    
    # 2. Check disk cache
    cache = _load_regen_cache()
    if domain in cache:
        count = cache[domain].get('count', 0)
        # Restore to session
        st.session_state[session_key] = count
        return count
    
    return 0


def increment_regen_count(domain: str) -> int:
    """
    Increment the regeneration count for a domain.
    
    Args:
        domain: The domain to increment
        
    Returns:
        New regeneration count
    """
    domain = _sanitize_domain(domain)
    if not domain:
        return 0
    
    current = get_regen_count(domain)
    new_count = current + 1
    
    # Update session state
    session_key = f"_regen_count_{domain}"
    st.session_state[session_key] = new_count
    
    # Update disk cache
    cache = _load_regen_cache()
    cache[domain] = {
        'count': new_count,
        'last_regen': datetime.now().isoformat()
    }
    _save_regen_cache(cache)
    
    logger.info(f"Incremented regen count for {domain} to {new_count}")
    return new_count


def reset_regen_count(domain: str) -> bool:
    """
    Reset the regeneration count for a domain.
    
    Args:
        domain: The domain to reset
        
    Returns:
        True if count was reset
    """
    domain = _sanitize_domain(domain)
    if not domain:
        return False
    
    # Clear from session state
    session_key = f"_regen_count_{domain}"
    st.session_state.pop(session_key, None)
    
    # Clear from disk cache
    cache = _load_regen_cache()
    if domain in cache:
        del cache[domain]
        _save_regen_cache(cache)
    
    logger.info(f"Reset regen count for {domain}")
    return True


def regen_limit_reached(domain: str, limit: int = REGEN_LIMIT) -> bool:
    """
    Check if regeneration limit has been reached for a domain.
    
    Args:
        domain: The domain to check
        limit: Maximum regenerations allowed (default: 5)
        
    Returns:
        True if limit has been reached
    """
    count = get_regen_count(domain)
    return count >= limit


def get_all_regen_counts() -> Dict[str, int]:
    """
    Get all regeneration counts.
    
    Returns:
        Dictionary mapping domain to count
    """
    cache = _load_regen_cache()
    return {domain: data.get('count', 0) for domain, data in cache.items()}
