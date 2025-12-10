#!/bin/bash
cd /workspaces/sales-engine
git add models.py app.py
git commit -m "Feature: Add comprehensive lead management with CSV import, AI enrichment, and service opportunity scoring

- Added enhanced Lead model with Google Places data
- Implemented industry detection and company size estimation
- Created multi-service opportunity scoring for all 10 Code Nest services
- Added CSV lead import with automatic website auditing
- Implemented AI-powered lead enrichment with GPT-4
- Generated service-specific pitch templates
- Created Lead Management dashboard with 4 tabs (Import, Database, Services, Insights)"

git push origin main
