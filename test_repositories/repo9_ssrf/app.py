from __future__ import annotations

import requests
from flask import Flask, request


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)

    @app.get("/fetch")
    def fetch() -> str:
        target_url = request.args.get("url", "")
        response = requests.get(target_url, timeout=5)
        return response.text

    return app
