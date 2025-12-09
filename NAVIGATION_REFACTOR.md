# Navigation & API Settings Refactor - Complete

## Overview

Your app has been completely refactored to implement:
- **Left-side navigation** replacing top horizontal tabs
- **API Settings page** for centralized API key management
- **Role-based navigation visibility** (admin sees more options than users)
- **Cleaner sidebar** focused on navigation and user management

---

## Key Changes

### 1. **Left-Side Navigation System**

**Before:** Horizontal tabs at the top of the page
```
[Dashboard] [Single Audit] [Bulk Processor] [Audit History] ...
```

**After:** Vertical navigation in the left sidebar
```
🦅 Code Nest Panel
━━━━━━━━━━━━━━━━━━
[Single Audit]        ← All users see this
[Bulk Audit]          ← Admins only
[API Settings]        ← Admins only
[Admin Settings]      ← Admins only
```

### 2. **API Settings Page**

A dedicated **API Settings** section (admin-only) where:
- OpenAI API key is configured
- Google PageSpeed API key is configured
- Slack Webhook URL is configured (optional)

**Location in Navigation:** Click "API Settings" in the left sidebar (admin only)

**Features:**
- Checks if OpenAI is connected via environment variable
- Shows status (✓ Configured / Not configured)
- Fields are password-type for security
- Session-based storage (keys stored in session, not on disk)

### 3. **Sidebar Cleanup**

**Removed from sidebar:**
- ❌ OpenAI API key input
- ❌ Google PageSpeed API key input
- ❌ Slack Webhook URL input

**Kept in sidebar:**
- ✅ Navigation buttons (dynamic based on role)
- ✅ System status badge (🟢 Active / 🟡 Limited)
- ✅ User info (name, role)
- ✅ Logout button
- ✅ 2FA setup checkbox (for admins)

### 4. **Role-Based Navigation**

**Regular Users see:**
- Single Audit

**Admin Users see:**
- Single Audit
- Bulk Audit
- API Settings
- Admin Settings

Navigation is dynamically built based on `st.session_state.get("is_admin")`

---

## Code Architecture

### Navigation State Management

```python
# Initialize in session state
if 'current_section' not in st.session_state:
    st.session_state.current_section = 'Single Audit'

# Store API keys in session
st.session_state.OPENAI_API_KEY
st.session_state.GOOGLE_API_KEY
st.session_state.SLACK_WEBHOOK
```

### Section Rendering

Main application uses `if/elif` logic instead of tabs:

```python
if st.session_state.current_section == "Single Audit":
    show_single_audit()

elif st.session_state.current_section == "Bulk Audit":
    if st.session_state.get("is_admin"):
        show_bulk_audit()
    else:
        st.error("Admin only")
```

### New Functions

1. **`show_api_settings()`** - API configuration page
2. **`show_single_audit()`** - Single website audit
3. **`show_bulk_audit()`** - Bulk CSV processing
4. **`show_audit_history()`** - Audit history (for future use)

---

## User Experience Flow

### For Regular Users:

1. Log in
2. See left sidebar with only "Single Audit" button
3. Click "Single Audit" → Audit page appears
4. Run audit → Results displayed with download option
5. Click logout when done

### For Admin Users:

1. Log in
2. See left sidebar with all 4 navigation buttons
3. Can click any button to switch sections:
   - **Single Audit**: Run individual audits
   - **Bulk Audit**: Upload CSV and process multiple sites
   - **API Settings**: Configure API keys
   - **Admin Settings**: Manage users, view analytics, system config
4. Navigation buttons highlight current section
5. Click logout when done

---

## API Key Management

### Where Keys Go:

1. **Environment Variables** (preferred):
   - `OPENAI_API_KEY` - Checked automatically on app start
   - If present, shown as "✓ Connected via environment variable"

2. **API Settings Page**:
   - Users can enter keys directly in the UI
   - Keys stored in `st.session_state` (session-based)
   - Keys cleared on page refresh or logout
   - Shown as password fields for security

3. **Usage**:
   - Functions use `st.session_state.OPENAI_API_KEY` and `st.session_state.GOOGLE_API_KEY`
   - Passed to `run_audit()` function
   - Features show warning if required key is missing

### Key Warning Messages:

If OpenAI key is not configured and user tries to use AI features:
```
⚠️ OpenAI API key not configured. Go to **API Settings** to configure it.
```

---

## Sidebar Layout

```
┌─────────────────────────────┐
│  🦅 Code Nest Panel         │
│  Navigation                 │
├─────────────────────────────┤
│                             │
│ [Single Audit] (primary)    │
│ [Bulk Audit] (if admin)     │
│ [API Settings] (if admin)   │
│ [Admin Settings] (if admin) │
│                             │
├─────────────────────────────┤
│  ─────────────────────      │
│  🟢 System: Active          │
│  ─────────────────────      │
│                             │
│  User: john_doe             │
│  Role: Admin                │
│                             │
│  [🚪 Logout]                │
│                             │
│  ─────────────────────      │
│  ☐ Setup 2FA                │
│    (expanded if admin)      │
│                             │
└─────────────────────────────┘
```

---

## Main Content Area

Now purely section-based:

```
┌────────────────────────────────────────────┐
│  🦅 Code Nest Sales Engine Pro            │
│  Intelligent Website Auditing...          │
│  ────────────────────────────────────────  │
│                                            │
│  [Content of current section below]        │
│                                            │
│  Single Audit:                             │
│  • Website URL input                       │
│  • Audit results                           │
│  • PDF download                            │
│                                            │
│  Bulk Audit (admin only):                  │
│  • CSV uploader                            │
│  • Batch processing                        │
│  • Results table                           │
│                                            │
│  API Settings (admin only):                │
│  • OpenAI API key input                    │
│  • Google PageSpeed key input              │
│  • Slack webhook input                     │
│                                            │
│  Admin Settings (admin only):              │
│  • User management                         │
│  • Analytics dashboard                     │
│  • System configuration                    │
│                                            │
└────────────────────────────────────────────┘
```

---

## Session State Variables

```python
st.session_state.current_section    # 'Single Audit', 'Bulk Audit', etc.
st.session_state.OPENAI_API_KEY     # OpenAI key from env or user input
st.session_state.GOOGLE_API_KEY     # Google key from user input
st.session_state.SLACK_WEBHOOK      # Slack webhook from user input
st.session_state.authenticated      # Boolean: user logged in?
st.session_state.current_user       # String: username
st.session_state.is_admin           # Boolean: admin privileges?
st.session_state.user_role          # String: 'admin' or 'user'
```

---

## Navigation Button Behavior

Buttons in the sidebar:
- Change color based on current section:
  - **Primary** (blue) if selected
  - **Secondary** (gray) if not selected
- Clicking a button:
  - Sets `st.session_state.current_section`
  - Calls `st.rerun()` to refresh
  - Main app re-renders with new section

```python
for item in nav_items:
    if st.button(
        item,
        key=f"nav_{item}",
        use_container_width=True,
        type="primary" if st.session_state.current_section == item else "secondary"
    ):
        st.session_state.current_section = item
        st.rerun()
```

---

## Backward Compatibility

✅ **All existing features preserved:**
- Single audit functionality unchanged
- Bulk processor logic unchanged
- Admin settings unchanged
- Database operations unchanged
- PDF generation and storage unchanged
- Authentication system unchanged
- 2FA setup unchanged

❌ **Only UI/Navigation changed:**
- Top horizontal tabs → left vertical navigation
- Sidebar API inputs → dedicated API Settings page
- Session-based API key storage (cleared on refresh/logout)

---

## Deployment

Changes have been committed to GitHub:
```
Commit: "Refactor: Implement left-side navigation with API Settings page"
Branch: main
Status: ✓ Live on Streamlit Cloud
```

The app automatically reloads with new navigation on next visit.

---

## Future Enhancements

Possible additions to the navigation:
- Dashboard section (metrics overview)
- Email Outreach section (currently admin sub-feature)
- Competitor Analysis section (currently admin sub-feature)
- Lead Management section
- Export/Reports section

These can be easily added by:
1. Adding section name to `nav_items` list
2. Creating new `show_section_name()` function
3. Adding `elif` clause in main rendering logic

---

## Troubleshooting

**Issue:** API keys not persisting after page refresh
- **Solution:** This is by design. Keys are session-based for security. Re-enter them or use environment variables.

**Issue:** User can't see their section
- **Solution:** Check role. Regular users only see "Single Audit". Admins see all 4 sections.

**Issue:** Navigation buttons not working
- **Solution:** Clear browser cache or hard refresh (Ctrl+Shift+R)

**Issue:** "API key not configured" warning on every audit
- **Solution:** Go to API Settings and enter your keys, or set environment variables

---

**Refactor Complete!** Your app now has a professional left-side navigation system with a dedicated API Settings page. 🎉
