"""
Flask application factory for Password Breach Monitoring (PBM).
Configures app routes, registers blueprints, and ensures database initialization.
"""

from pathlib import Path
from flask import Flask, render_template
from app.db import init_db
from app.api import api_bp

BASE_DIR = Path(__file__).resolve().parent.parent

def create_app():
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static")
    )

    # Initialize SQLite database if it doesn't exist or is empty
    with app.app_context():
        init_db()

    # Register API blueprint
    app.register_blueprint(api_bp)

    @app.route("/")
    def index():
        return render_template("index.html")

    return app
