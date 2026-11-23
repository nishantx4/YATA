from __future__ import annotations

import base64
import pickle

from flask import Flask, request


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)

    @app.post("/load")
    def load() -> object:
        data = request.form.get("data", "")
        try:
            obj = pickle.loads(base64.b64decode(data))
        except Exception:
            return "invalid data", 400
        return str(obj)

    return app
