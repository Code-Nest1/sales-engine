#!/bin/bash
cd /workspaces/sales-engine
git add app.py
git commit -m "Fix: Persist API keys across logout/login by reloading from user account

- Added reload_user_api_keys() function to restore keys after login
- Load keys from user account on successful login (both normal and 2FA paths)
- Reload keys when restoring session from query parameters
- Environment variables still take highest priority
- User-saved keys are now properly restored every session"

git push origin main
