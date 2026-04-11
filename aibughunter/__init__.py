"""AI Bug Hunter - AI-powered automated bug hunting platform."""

__version__ = "0.1.0"
__author__ = "AI Bug Hunter Team"

import warnings

# Suppress common warnings that don't affect functionality
warnings.filterwarnings("ignore", category=DeprecationWarning, module="nmap")

def main():
    """Entry point for the CLI."""
    from aibughunter.cli import app
    app()

if __name__ == "__main__":
    main()
