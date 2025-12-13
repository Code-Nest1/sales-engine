"""
Persistence Layer for Sales Engine
===================================

This module provides robust persistence for all audit-related data,
ensuring state survives refresh, navigation, logout, and tab closure.

Modules:
--------
- audit_state: Core audit data persistence (session + DB)
- ai_cache: AI analysis caching to prevent recomputation
- pdf_context: PDF generation context preservation
- navigation_state: Navigation and deep-linking state

Usage:
------
    from persistence import (
        # Audit State
        persist_audit_data,
        load_audit_data,
        get_current_audit,
        set_current_audit,
        clear_current_audit,
        
        # AI Cache
        get_ai_cache,
        save_ai_cache,
        ai_cache_exists,
        clear_ai_cache,
        
        # Regeneration Tracking
        get_regen_count,
        increment_regen_count,
        reset_regen_count,
        regen_limit_reached,
        
        # PDF Context
        store_pdf_context,
        load_pdf_context,
        
        # Navigation
        save_navigation_state,
        load_navigation_state,
        clear_navigation_state,
        
        # Initialization
        init_app_session_persistence
    )

Author: Code Nest LLC
Version: 1.0.0
"""

# Audit State Management
from .audit_state import (
    persist_audit_data,
    load_audit_data,
    get_current_audit,
    set_current_audit,
    clear_current_audit,
    get_audit_from_db,
    rebuild_audit_data_from_db,
)

# AI Analysis Cache
from .ai_cache import (
    get_ai_cache,
    save_ai_cache,
    ai_cache_exists,
    clear_ai_cache,
    get_regen_count,
    increment_regen_count,
    reset_regen_count,
    regen_limit_reached,
    REGEN_LIMIT,
)

# PDF Context Persistence
from .pdf_context import (
    store_pdf_context,
    load_pdf_context,
    clear_pdf_context,
    get_pdf_context_or_current,
)

# Navigation State
from .navigation_state import (
    save_navigation_state,
    load_navigation_state,
    clear_navigation_state,
    get_deep_link_audit_id,
    sync_query_params,
    restore_navigation_on_refresh,
)

# Centralized Initialization
from .session_init import (
    init_app_session_persistence,
    reset_persistence_state,
    get_persistence_status,
    on_logout_cleanup,
)

__all__ = [
    # Audit State
    'persist_audit_data',
    'load_audit_data',
    'get_current_audit',
    'set_current_audit',
    'clear_current_audit',
    'get_audit_from_db',
    'rebuild_audit_data_from_db',
    
    # AI Cache
    'get_ai_cache',
    'save_ai_cache',
    'ai_cache_exists',
    'clear_ai_cache',
    'get_regen_count',
    'increment_regen_count',
    'reset_regen_count',
    'regen_limit_reached',
    'REGEN_LIMIT',
    
    # PDF Context
    'store_pdf_context',
    'load_pdf_context',
    'clear_pdf_context',
    'get_pdf_context_or_current',
    
    # Navigation
    'save_navigation_state',
    'load_navigation_state',
    'clear_navigation_state',
    'get_deep_link_audit_id',
    'sync_query_params',
    'restore_navigation_on_refresh',
    
    # Initialization
    'init_app_session_persistence',
    'reset_persistence_state',
    'get_persistence_status',
    'on_logout_cleanup',
]
