# API Key Storage - Developer Guidelines

## ⚠️ CRITICAL: This Issue Has Been Permanently Fixed

**Date Fixed**: December 10, 2025  
**Commit**: `7d18099` + `e264bed`  
**Status**: PRODUCTION-READY

### The Problem (Now Resolved)
API keys were being lost after being saved and the page reloaded. This has been **permanently fixed** by migrating from JSON file storage to database-backed storage.

## Architecture

### Current System (CORRECT)
```
User adds API key
    ↓
save_user_api_key() → Encrypts key
    ↓
Database save (ATOMIC transaction)
    ↓
Page reloads
    ↓
Session initialization (ALWAYS loads from DB)
    ↓
Key is available reliably
```

### How It Works
1. **Storage**: API keys stored in `User.api_keys` (JSON column in database)
2. **Encryption**: Keys encrypted with Fernet before storage
3. **Loading**: On EVERY page load, if user is logged in, keys are reloaded from database
4. **Persistence**: Database transactions ensure atomic saves

## Code Locations

### API Key Functions
- **Get keys**: `get_user_api_keys()` at line 1311 (database-backed)
- **Save keys**: `save_user_api_key()` at line 1350 (database-backed)
- **Delete keys**: `delete_user_api_key()` at line 1370 (database-backed)

### Session Initialization
- **Lines 1647-1673**: ALWAYS-RELOAD pattern
- **Key section**:
  ```python
  if st.session_state.get("current_user"):
      # User is logged in - ALWAYS reload from database
      user_keys = get_user_api_keys(st.session_state.get("current_user"))
      st.session_state.OPENAI_API_KEY = env_openai or user_keys.get("openai", "")
  ```

### Migration & Sync
- **Migration**: `migrate_api_keys_from_json_to_db()` at line 1410
- **Sync on login**: `ensure_user_in_database()` at line 1430

## DO's and DON'Ts

### ✅ DO These Things

1. **Always use database functions for API keys**
   ```python
   # CORRECT - uses database
   keys = get_user_api_keys(username)
   save_user_api_key(username, "openai", key_value)
   ```

2. **Always reload from database when user logs in**
   ```python
   # CORRECT - called in login and 2FA paths
   reload_user_api_keys()
   ```

3. **Use encryption for sensitive keys**
   ```python
   # CORRECT - keys are encrypted before storage
   user.api_keys[key_name] = encrypt_key(key_value)
   ```

4. **Handle database errors gracefully**
   ```python
   # CORRECT - with error handling
   try:
       db = get_db()
       # ... database operation ...
       db.commit()
   except Exception as e:
       logger.error(f"Error: {e}")
       if db:
           db.close()
   ```

### ❌ DON'T Do These Things

1. **❌ Don't store API keys in session state only**
   ```python
   # WRONG - session state is not persistent!
   st.session_state.OPENAI_API_KEY = key_value
   # This will be lost on reload
   ```

2. **❌ Don't read/write directly to users.json for API keys**
   ```python
   # WRONG - JSON file is unreliable
   users = load_users()
   users[username]["api_keys"]["openai"] = key_value
   save_users(users)
   ```

3. **❌ Don't use one-time initialization for persistent data**
   ```python
   # WRONG - only runs once, won't reload
   if 'API_KEY' not in st.session_state:
       st.session_state.API_KEY = ...  # This won't reload on subsequent calls
   ```

4. **❌ Don't skip database operations or commit**
   ```python
   # WRONG - data might not be persisted
   user.api_keys[key_name] = value
   # Missing: db.commit()
   ```

5. **❌ Don't forget to close database connections**
   ```python
   # WRONG - connection leak
   db = get_db()
   user = db.query(User).first()
   # Missing: db.close()
   ```

6. **❌ Don't modify API key functions without documentation**
   ```python
   # WRONG - changes could reintroduce the bug
   # Any changes to get_user_api_keys, save_user_api_key,
   # or session initialization must be carefully reviewed
   ```

## Testing Checklist

Before deploying ANY changes that touch API keys:

- [ ] Add API key via UI
- [ ] Verify it's saved (check database)
- [ ] Refresh page (Ctrl+F5)
- [ ] Key still present in API Settings
- [ ] Logout and login again
- [ ] Key still present
- [ ] Repeat with multiple keys (OpenAI, Google, Slack)
- [ ] All keys persist

## If You Need to Modify API Key Code

### Before Making Changes
1. Read `API_PERSISTENCE_FIX.md` (complete technical details)
2. Read `FIX_SUMMARY.md` (implementation summary)
3. Understand why it was broken (see "Root Cause Analysis")
4. Understand why the fix works (see "Solution")

### Making Changes Safely
1. **Don't** move API keys back to JSON files
2. **Do** keep using database storage
3. **Do** maintain the always-reload pattern
4. **Do** add comprehensive error handling
5. **Do** test thoroughly before commit
6. **Do** document any changes

### Code Review Guidelines
If reviewing someone else's changes to API key code:
- ✅ Verify database transactions are used
- ✅ Check error handling is present
- ✅ Ensure session initialization pattern is preserved
- ✅ Look for any one-time initialization patterns (anti-pattern!)
- ✅ Verify db.close() is called in error paths

## Monitoring

### What to Monitor in Production
1. Check logs for API key operation errors
   ```bash
   tail -f logs/app.log | grep "API key"
   ```

2. Monitor database for API key changes
   ```sql
   SELECT username, api_keys_updated_at FROM users 
   WHERE api_keys_updated_at > NOW() - INTERVAL '1 hour';
   ```

3. Track failed saves/loads in application logs

### Red Flags (If You See These, Something is Wrong)
- Users reporting "API key disappeared"
- "No such column: api_keys" errors (migration didn't run)
- "API keys missing after page reload" (back to old pattern)
- "Can't connect to database" errors (database down)

## References

### Document Files
- `API_PERSISTENCE_FIX.md` - Technical deep dive
- `FIX_SUMMARY.md` - Implementation summary
- This file (`API_KEY_STORAGE_GUIDELINES.md`) - Developer guide

### Related Files
- `models.py` - User model definition (lines 131-143)
- `app.py` - API key functions and initialization (lines 1311-1673)

### Key Commits
- `7d18099` - Initial fix implementation
- `e264bed` - Documentation

## Future Improvements

These are suggestions for future work (NOT needed for current fix):

1. **Remove JSON storage entirely** (after migration period)
   - Once all users are migrated to DB
   - Can deprecate `load_users()`, `save_users()`

2. **Add API key audit logging**
   - Track who changed keys and when
   - Build on `api_keys_updated_at` timestamp

3. **Implement key rotation**
   - Warn users about old keys
   - Automatic rotation policy

4. **Add key scopes/permissions**
   - Limit what each key can do
   - Security best practice

## Questions?

If you have questions about API key storage:
1. Check the three documentation files above
2. Look at the commit diff: `git show 7d18099`
3. Review the actual code in `app.py` and `models.py`
4. Ask during code review

---

**Remember**: This fix took significant effort to diagnose and implement correctly. Please preserve it by following these guidelines. Don't revert to JSON storage or one-time initialization patterns!
