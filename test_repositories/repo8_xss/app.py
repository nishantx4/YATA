from __future__ import annotations

from flask import Flask, request


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)

    @app.get("/greet")
    def greet() -> str:
        name = request.args.get("name", "Guest")
        return f"<h1>Hello {name}</h1>"

    return app
