from __future__ import annotations

from flask import Flask, render_template_string, request


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)

    @app.get("/hello")
    def hello() -> str:
        name = request.args.get("name", "World")
        template = f"<h1>Hello {name}</h1>"
        return render_template_string(template)

    return app
