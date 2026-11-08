#!/bin/bash
# Start the Dental Clinic backend + web dashboard.
#   ./run.sh            -> http://localhost:8000  (web) and /api (app)
#   DENTAL_SECRET=... ./run.sh   -> set your own secret (change before VPS!)
cd "$(dirname "$0")"
if [ ! -d venv ]; then
  python3 -m venv venv
  ./venv/bin/pip install -r requirements.txt
fi
exec ./venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000
