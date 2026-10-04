#!/usr/bin/env python3
"""
Application runner script for Password Breach Monitoring (PBM).
Starts the Flask server on http://127.0.0.1:5000
"""

from app import create_app

app = create_app()

if __name__ == "__main__":
    print("Starting Password Breach Monitoring Server on http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=True)
