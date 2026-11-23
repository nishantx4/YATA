from __future__ import annotations

from flask import Flask, redirect, request


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)

    @app.get("/goto")
    def goto() -> object:
        target = request.args.get("next", "/")
        return redirect(target)

    return app
