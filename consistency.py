"""
Consistency Layer for Sales Engine
===================================

This module provides centralized functions for normalizing and serializing
all data models (Audit, Lead, BulkScan) ensuring consistency across the app.

Usage:
    from consistency import normalize_audit, normalize_lead, normalize_bulk_result
    
    # Convert ORM or dict to normalized dict
    audit_dict = normalize_audit(audit_orm_or_dict)
    lead_dict = normalize_lead(lead_orm_or_dict)
    bulk_dict = normalize_bulk_result(bulk_orm_or_dict)

All functions handle both ORM objects and existing dicts, returning
fully normalized dicts with all expected fields and safe defaults.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union

# ============================================================================
# FIELD MAPPINGS & ALIASES
# ============================================================================

# Audit field aliases (old_name -> canonical_name)
AUDIT_FIELD_ALIASES = {
    "score": "health_score",
    "timestamp": "created_at",
    "psi": "psi_score",
    "tech": "tech_stack",
}

# Lead field aliases
LEAD_FIELD_ALIASES = {
    "company": "company_name",
    "status": "pipeline_stage",  # Legacy alias
}

# Default values for missing fields
AUDIT_DEFAULTS = {
    "id": None,
    "url": "",
    "domain": "",
    "health_score": 0,
    "psi_score": None,
    "domain_age": "",
    "tech_stack": [],
    "issues": [],
    "issue_count": 0,
    "emails_found": [],
    "ai_summary": "",
    "ai_impact": "",
    "ai_solutions": "",
    "ai_email": "",
    "ai_email_subject": "",
    "username": "",
    "source": "single",
    "status": "",
    "comparison_group": "",
    "is_scheduled": False,
    "created_at": None,
    "timestamp": None,  # Alias for created_at
}

LEAD_DEFAULTS = {
    "id": None,
    "domain": "",
    "email": "",
    "company_name": "",
    "phone": "",
    "address": "",
    "place_id": "",
    "city": "",
    "state": "",
    "zipcode": "",
    "latitude": None,
    "longitude": None,
    "health_score": None,
    "opportunity_rating": 0,
    "industry": "",
    "company_size": "",
    "estimated_revenue": "",
    "services_needed": [],
    "service_priorities": {},
    "status": "new",
    "notes": "",
    "ai_enrichment": None,
    "approached": False,
    "approached_date": None,
    "follow_up_date": None,
    "lead_status": "warm",
    "interested": "maybe",
    "pipeline_stage": "new",
    "assigned_user": "",
    "source": "single",
    "last_audit_id": None,
    "created_at": None,
    "updated_at": None,
}

BULK_SCAN_DEFAULTS = {
    "id": None,
    "session_id": "",
    "status": "running",
    "total_urls": 0,
    "processed_urls": 0,
    "urls": [],
    "results": {},
    "paused_at_index": 0,
    "created_at": None,
    "updated_at": None,
}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _safe_isoformat(value: Any) -> Optional[str]:
    """Convert datetime to ISO format string, or return string as-is."""
    if value is None:
        return None
    if hasattr(value, 'isoformat'):
        return value.isoformat()
    if isinstance(value, str):
        return value
    return str(value)


def _safe_int(value: Any, default: int = 0) -> int:
    """Safely convert value to int."""
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _safe_list(value: Any) -> list:
    """Ensure value is a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return []


def _safe_dict(value: Any) -> dict:
    """Ensure value is a dict."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    return {}


def _safe_bool(value: Any, default: bool = False) -> bool:
    """Safely convert value to bool."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.lower() in ('true', '1', 'yes')
    return default


def _safe_str(value: Any, default: str = "") -> str:
    """Safely convert value to string."""
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return str(value)


def _get_attr_or_key(obj: Any, key: str, default: Any = None) -> Any:
    """Get attribute from ORM object or key from dict."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


# ============================================================================
# AUDIT NORMALIZATION
# ============================================================================

def normalize_audit(audit: Any) -> Dict[str, Any]:
    """
    Normalize an Audit object (ORM or dict) to a consistent dictionary.
    
    This function:
    - Handles both ORM Audit objects and existing dicts
    - Applies field aliases (score -> health_score, etc.)
    - Ensures all expected fields exist with safe defaults
    - Converts datetime fields to ISO strings
    - Calculates issue_count from issues list
    
    Args:
        audit: Audit ORM object or dict
    
    Returns:
        Normalized dict with all audit fields
    """
    if audit is None:
        return dict(AUDIT_DEFAULTS)
    
    is_dict = isinstance(audit, dict)
    
    # Extract values with safe fallbacks
    def get(key: str, default: Any = None) -> Any:
        if is_dict:
            # Check for aliases
            value = audit.get(key)
            if value is None and key in AUDIT_FIELD_ALIASES:
                value = audit.get(AUDIT_FIELD_ALIASES[key])
            # Check reverse aliases
            for alias, canonical in AUDIT_FIELD_ALIASES.items():
                if canonical == key and value is None:
                    value = audit.get(alias)
            return value if value is not None else default
        else:
            return getattr(audit, key, default)
    
    # Build normalized dict
    created_at = _safe_isoformat(get("created_at"))
    issues = _safe_list(get("issues"))
    
    result = {
        # Core identification
        "id": get("id"),
        "url": _safe_str(get("url")),
        "domain": _safe_str(get("domain")),
        
        # Scores (with aliases)
        "health_score": _safe_int(get("health_score") or get("score"), 0),
        "score": _safe_int(get("health_score") or get("score"), 0),  # Alias
        "psi_score": get("psi_score") or get("psi"),
        "psi": get("psi_score") or get("psi"),  # Alias
        
        # Technical details
        "domain_age": _safe_str(get("domain_age")),
        "tech_stack": _safe_list(get("tech_stack") or get("tech")),
        "tech": _safe_list(get("tech_stack") or get("tech")),  # Alias
        
        # Issues
        "issues": issues,
        "issue_count": len(issues),
        
        # Contact info
        "emails_found": _safe_list(get("emails_found")),
        
        # AI insights
        "ai_summary": _safe_str(get("ai_summary")),
        "ai_impact": _safe_str(get("ai_impact")),
        "ai_solutions": _safe_str(get("ai_solutions")),
        "ai_email": _safe_str(get("ai_email")),
        "ai_email_subject": _safe_str(get("ai_email_subject")),
        
        # Metadata
        "username": _safe_str(get("username")),
        "source": _safe_str(get("source")) or "single",
        "status": _safe_str(get("status")),
        "comparison_group": _safe_str(get("comparison_group")),
        "is_scheduled": _safe_bool(get("is_scheduled")),
        
        # Timestamps (with alias)
        "created_at": created_at,
        "timestamp": created_at,  # Alias for backward compatibility
    }
    
    return result


def normalize_audit_list(audits: List[Any]) -> List[Dict[str, Any]]:
    """Normalize a list of audits."""
    return [normalize_audit(a) for a in audits]


# ============================================================================
# LEAD NORMALIZATION
# ============================================================================

def normalize_lead(lead: Any) -> Dict[str, Any]:
    """
    Normalize a Lead object (ORM or dict) to a consistent dictionary.
    
    This function:
    - Handles both ORM Lead objects and existing dicts
    - Ensures all CRM fields exist with safe defaults
    - Converts datetime fields to ISO strings
    - Ensures boolean fields are proper booleans
    
    Args:
        lead: Lead ORM object or dict
    
    Returns:
        Normalized dict with all lead fields
    """
    if lead is None:
        return dict(LEAD_DEFAULTS)
    
    is_dict = isinstance(lead, dict)
    
    def get(key: str, default: Any = None) -> Any:
        if is_dict:
            value = lead.get(key)
            if value is None and key in LEAD_FIELD_ALIASES:
                value = lead.get(LEAD_FIELD_ALIASES[key])
            return value if value is not None else default
        else:
            return getattr(lead, key, default)
    
    result = {
        # Core identification
        "id": get("id"),
        "domain": _safe_str(get("domain")),
        "email": _safe_str(get("email")),
        "company_name": _safe_str(get("company_name") or get("company")),
        
        # Contact info
        "phone": _safe_str(get("phone")),
        "address": _safe_str(get("address")),
        "place_id": _safe_str(get("place_id")),
        "city": _safe_str(get("city")),
        "state": _safe_str(get("state")),
        "zipcode": _safe_str(get("zipcode")),
        "latitude": get("latitude"),
        "longitude": get("longitude"),
        
        # Scoring
        "health_score": get("health_score"),
        "opportunity_rating": _safe_int(get("opportunity_rating"), 0),
        
        # Business info
        "industry": _safe_str(get("industry")),
        "company_size": _safe_str(get("company_size")),
        "estimated_revenue": _safe_str(get("estimated_revenue")),
        "services_needed": _safe_list(get("services_needed")),
        "service_priorities": _safe_dict(get("service_priorities")),
        
        # Legacy status
        "status": _safe_str(get("status")) or "new",
        
        # Notes and AI
        "notes": _safe_str(get("notes")),
        "ai_enrichment": get("ai_enrichment"),
        
        # CRM fields
        "approached": _safe_bool(get("approached"), False),
        "approached_date": _safe_isoformat(get("approached_date")),
        "follow_up_date": _safe_isoformat(get("follow_up_date")),
        "lead_status": _safe_str(get("lead_status")) or "warm",
        "interested": _safe_str(get("interested")) or "maybe",
        "pipeline_stage": _safe_str(get("pipeline_stage")) or "new",
        "assigned_user": _safe_str(get("assigned_user")),
        
        # Source tracking
        "source": _safe_str(get("source")) or "single",
        "last_audit_id": get("last_audit_id"),
        
        # Timestamps
        "created_at": _safe_isoformat(get("created_at")),
        "updated_at": _safe_isoformat(get("updated_at")),
    }
    
    return result


def normalize_lead_list(leads: List[Any]) -> List[Dict[str, Any]]:
    """Normalize a list of leads."""
    return [normalize_lead(l) for l in leads]


# ============================================================================
# BULK SCAN NORMALIZATION
# ============================================================================

def normalize_bulk_result(bulk: Any) -> Dict[str, Any]:
    """
    Normalize a BulkScan object (ORM or dict) to a consistent dictionary.
    
    Args:
        bulk: BulkScan ORM object or dict
    
    Returns:
        Normalized dict with all bulk scan fields
    """
    if bulk is None:
        return dict(BULK_SCAN_DEFAULTS)
    
    is_dict = isinstance(bulk, dict)
    
    def get(key: str, default: Any = None) -> Any:
        if is_dict:
            return bulk.get(key, default)
        else:
            return getattr(bulk, key, default)
    
    result = {
        "id": get("id"),
        "session_id": _safe_str(get("session_id")),
        "status": _safe_str(get("status")) or "running",
        "total_urls": _safe_int(get("total_urls"), 0),
        "processed_urls": _safe_int(get("processed_urls"), 0),
        "urls": _safe_list(get("urls")),
        "results": _safe_dict(get("results")),
        "paused_at_index": _safe_int(get("paused_at_index"), 0),
        "created_at": _safe_isoformat(get("created_at")),
        "updated_at": _safe_isoformat(get("updated_at")),
    }
    
    return result


def normalize_bulk_list(bulks: List[Any]) -> List[Dict[str, Any]]:
    """Normalize a list of bulk scans."""
    return [normalize_bulk_result(b) for b in bulks]


# ============================================================================
# VALIDATION HELPERS
# ============================================================================

def ensure_audit_fields(audit_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure all required audit fields exist in a dictionary.
    
    This patches legacy audits that may be missing newer fields.
    """
    result = dict(AUDIT_DEFAULTS)
    result.update(audit_dict)
    
    # Ensure issue_count is calculated
    if "issues" in result:
        result["issue_count"] = len(_safe_list(result["issues"]))
    
    # Ensure timestamp alias
    if result.get("created_at") and not result.get("timestamp"):
        result["timestamp"] = result["created_at"]
    elif result.get("timestamp") and not result.get("created_at"):
        result["created_at"] = result["timestamp"]
    
    # Ensure score aliases
    if result.get("health_score") and not result.get("score"):
        result["score"] = result["health_score"]
    elif result.get("score") and not result.get("health_score"):
        result["health_score"] = result["score"]
    
    return result


def ensure_lead_fields(lead_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure all required lead fields exist in a dictionary.
    
    This patches legacy leads that may be missing CRM fields.
    """
    result = dict(LEAD_DEFAULTS)
    result.update(lead_dict)
    
    # Ensure boolean fields are booleans
    result["approached"] = _safe_bool(result.get("approached"), False)
    
    # Ensure status fields have valid values
    if result["lead_status"] not in ("hot", "warm", "cold"):
        result["lead_status"] = "warm"
    
    if result["interested"] not in ("yes", "no", "maybe"):
        result["interested"] = "maybe"
    
    if result["pipeline_stage"] not in ("new", "contacted", "follow-up", "qualified", "proposal", "closed"):
        result["pipeline_stage"] = "new"
    
    return result


# ============================================================================
# EXPORT HELPERS
# ============================================================================

def get_safe_export_columns(df_columns: List[str], preferred: List[str] = None) -> List[str]:
    """
    Get safe default columns for export based on what exists in dataframe.
    
    Args:
        df_columns: List of columns that exist in the dataframe
        preferred: List of preferred column names (in order of preference)
    
    Returns:
        List of columns to use as defaults (only those that exist)
    """
    if preferred is None:
        preferred = ["domain", "health_score", "psi_score", "status", "created_at", "timestamp"]
    
    defaults = [col for col in preferred if col in df_columns]
    
    # If no preferred columns exist, use first few available
    if not defaults and df_columns:
        defaults = df_columns[:min(4, len(df_columns))]
    
    return defaults


def safe_timestamp_slice(timestamp: Any, length: int = 10) -> str:
    """
    Safely slice a timestamp for display.
    
    Args:
        timestamp: Timestamp value (datetime, string, or None)
        length: Number of characters to return (default 10 for YYYY-MM-DD)
    
    Returns:
        Sliced timestamp string or "N/A"
    """
    if timestamp is None:
        return "N/A"
    
    ts_str = _safe_isoformat(timestamp) if hasattr(timestamp, 'isoformat') else str(timestamp)
    
    if len(ts_str) >= length:
        return ts_str[:length]
    
    return ts_str or "N/A"


# ============================================================================
# COMPATIBILITY ALIASES
# ============================================================================

# These provide backward compatibility with existing code
lead_to_dict = normalize_lead
audit_to_dict = normalize_audit
bulk_to_dict = normalize_bulk_result

_lead_to_dict = normalize_lead
_audit_to_dict = normalize_audit
_bulk_to_dict = normalize_bulk_result


# ============================================================================
# CRASH-PROOF FIELD RECOVERY (Phase 5 Step 3)
# ============================================================================

def ensure_audit_defaults(audit: Any) -> Dict[str, Any]:
    """
    Ensure all critical audit fields exist with safe defaults.
    
    Use this before rendering to guarantee no KeyError or missing field crashes.
    This goes beyond normalize_audit by ensuring UI-critical fields are always present.
    
    Args:
        audit: Audit dict (should already be normalized, but handles any input)
    
    Returns:
        Dict with all required fields guaranteed
    """
    # First normalize if not already a dict
    if not isinstance(audit, dict):
        audit = normalize_audit(audit)
    
    # Start with defaults
    result = dict(AUDIT_DEFAULTS)
    result.update(audit)
    
    # Ensure critical numeric fields
    if result.get("health_score") is None:
        result["health_score"] = 0
    result["score"] = result["health_score"]  # Alias
    
    if result.get("psi_score") is None:
        result["psi_score"] = 0
    result["psi"] = result["psi_score"]  # Alias
    
    # Ensure critical list fields
    if not isinstance(result.get("issues"), list):
        result["issues"] = []
    result["issue_count"] = len(result["issues"])
    
    if not isinstance(result.get("tech_stack"), list):
        result["tech_stack"] = []
    result["tech"] = result["tech_stack"]  # Alias
    
    if not isinstance(result.get("emails_found"), list):
        result["emails_found"] = []
    
    # Ensure string fields
    if not result.get("domain"):
        result["domain"] = "Unknown"
    
    if not result.get("domain_age"):
        result["domain_age"] = "Unknown"
    
    if not result.get("created_at"):
        result["created_at"] = ""
    result["timestamp"] = result["created_at"]  # Alias
    
    # Ensure AI fields are a proper dict structure
    result["ai"] = {
        "summary": _safe_str(result.get("ai_summary")),
        "impact": _safe_str(result.get("ai_impact")),
        "solutions": _safe_str(result.get("ai_solutions")),
        "email": _safe_str(result.get("ai_email")),
        "email_subject": _safe_str(result.get("ai_email_subject")),
    }
    
    return result


def ensure_lead_defaults(lead: Any) -> Dict[str, Any]:
    """
    Ensure all critical CRM lead fields exist with safe defaults.
    
    Use this before rendering to guarantee no KeyError or missing field crashes.
    
    Args:
        lead: Lead dict (should already be normalized, but handles any input)
    
    Returns:
        Dict with all required CRM fields guaranteed
    """
    # First normalize if not already a dict
    if not isinstance(lead, dict):
        lead = normalize_lead(lead)
    
    # Start with defaults
    result = dict(LEAD_DEFAULTS)
    result.update(lead)
    
    # Ensure critical boolean fields
    result["approached"] = _safe_bool(result.get("approached"), False)
    
    # Ensure date fields are None or valid
    if result.get("approached_date") == "":
        result["approached_date"] = None
    if result.get("follow_up_date") == "":
        result["follow_up_date"] = None
    
    # Ensure status fields have valid enum values
    if result.get("lead_status") not in ("hot", "warm", "cold"):
        result["lead_status"] = "cold"
    
    if result.get("pipeline_stage") not in ("new", "contacted", "follow-up", "qualified", "proposal", "closed"):
        result["pipeline_stage"] = "new"
    
    if result.get("interested") not in ("yes", "no", "maybe"):
        result["interested"] = "no"
    
    # Ensure string fields
    if not result.get("notes"):
        result["notes"] = ""
    if not result.get("assigned_user"):
        result["assigned_user"] = ""
    if not result.get("phone"):
        result["phone"] = ""
    if not result.get("domain"):
        result["domain"] = ""
    
    # Ensure numeric fields
    if result.get("last_audit_id") is None:
        result["last_audit_id"] = None
    if result.get("health_score") is None:
        result["health_score"] = None  # Keep None for "not scanned"
    
    # Ensure list/dict fields
    if not isinstance(result.get("services_needed"), list):
        result["services_needed"] = []
    if not isinstance(result.get("service_priorities"), dict):
        result["service_priorities"] = {}
    
    return result


def ensure_bulk_defaults(bulk: Any) -> Dict[str, Any]:
    """
    Ensure all critical bulk scan fields exist with safe defaults.
    
    Use this before rendering to guarantee no KeyError or missing field crashes.
    
    Args:
        bulk: BulkScan dict (should already be normalized, but handles any input)
    
    Returns:
        Dict with all required bulk scan fields guaranteed
    """
    # First normalize if not already a dict
    if not isinstance(bulk, dict):
        bulk = normalize_bulk_result(bulk)
    
    # Start with defaults
    result = dict(BULK_SCAN_DEFAULTS)
    result.update(bulk)
    
    # Ensure critical numeric fields
    if result.get("processed_urls") is None:
        result["processed_urls"] = 0
    if result.get("total_urls") is None:
        result["total_urls"] = 0
    if result.get("paused_at_index") is None:
        result["paused_at_index"] = 0
    
    # Ensure dict fields
    if not isinstance(result.get("results"), dict):
        result["results"] = {}
    
    # Ensure list fields
    if not isinstance(result.get("urls"), list):
        result["urls"] = []
    
    # Ensure status is valid
    if result.get("status") not in ("running", "paused", "completed", "error"):
        result["status"] = "running"
    
    # Ensure session_id
    if not result.get("session_id"):
        result["session_id"] = ""
    
    return result


def safe_render_audit(audit: Any) -> Dict[str, Any]:
    """
    Full safety wrapper: normalize + ensure defaults.
    Use this in UI rendering functions.
    """
    return ensure_audit_defaults(normalize_audit(audit))


def safe_render_lead(lead: Any) -> Dict[str, Any]:
    """
    Full safety wrapper: normalize + ensure defaults.
    Use this in UI rendering functions.
    """
    return ensure_lead_defaults(normalize_lead(lead))


def safe_render_bulk(bulk: Any) -> Dict[str, Any]:
    """
    Full safety wrapper: normalize + ensure defaults.
    Use this in UI rendering functions.
    """
    return ensure_bulk_defaults(normalize_bulk_result(bulk))
