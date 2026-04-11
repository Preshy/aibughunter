#!/usr/bin/env python
"""
AI Bug Hunter Marketing Site Launcher

This script starts the marketing/landing page server.
Deploy to Fly.io with: fly launch
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from aibughunter.web.marketing import app
import uvicorn


if __name__ == "__main__":
    uvicorn.run(
        "aibughunter.web.marketing:app",
        host="0.0.0.0",
        port=8080,
        reload=False,
    )
