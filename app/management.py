"""Browser-based management interface for the PlayrServers control plane."""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .database import Database
from .models import User


TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def create_app(
    *,
    database: Database,
    api_base_url: Optional[str] = None,
    session_secret: Optional[str] = None,
) -> FastAPI:
    """Create the management web application."""

    if session_secret is None:
        session_secret = os.getenv("MANAGEMENT_SESSION_SECRET")
    if not session_secret:
        raise RuntimeError(
            "MANAGEMENT_SESSION_SECRET must be configured to use the management interface"
        )

    if api_base_url is None:
        api_base_url = os.getenv("MANAGEMENT_PUBLIC_API_URL", "https://api.playrservers.com")

    app = FastAPI(
        title="PlayrServers Management Interface",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.database = database
    app.state.public_api_url = api_base_url

    secure_cookie = os.getenv("MANAGEMENT_SESSION_SECURE", "true").strip().lower() not in {
        "0",
        "false",
        "no",
    }

    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        session_cookie="playrservers_session",
        https_only=secure_cookie,
        same_site="lax",
        max_age=60 * 60 * 24 * 7,
    )

    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
    templates.env.globals["api_base_url"] = api_base_url
    templates.env.globals["now"] = datetime.utcnow

    def _get_current_user(request: Request) -> Optional[User]:
        user_id = request.session.get("user_id")
        if not user_id:
            return None
        user = database.get_user(int(user_id))
        if user is None:
            request.session.pop("user_id", None)
        return user

    def _redirect_to_login(request: Request) -> RedirectResponse:
        return RedirectResponse(
            request.url_for("show_login"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request):
        user = _get_current_user(request)
        if user is None:
            return RedirectResponse(
                request.url_for("show_login"),
                status_code=status.HTTP_303_SEE_OTHER,
            )
        return RedirectResponse(
            request.url_for("dashboard"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.get("/login", response_class=HTMLResponse, name="show_login")
    async def login_form(request: Request):
        user = _get_current_user(request)
        if user is not None:
            return RedirectResponse(
                request.url_for("dashboard"),
                status_code=status.HTTP_303_SEE_OTHER,
            )
        error = request.session.pop("login_error", None)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": error},
        )

    @app.post("/login", name="process_login")
    async def process_login(request: Request, email: str = Form(...), password: str = Form(...)):
        user = database.authenticate_user(email, password)
        if user is None:
            request.session["login_error"] = "Invalid email or password."
            return RedirectResponse(
                request.url_for("show_login"),
                status_code=status.HTTP_303_SEE_OTHER,
            )

        request.session.clear()
        request.session["user_id"] = user.id
        return RedirectResponse(
            request.url_for("dashboard"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.get("/logout", name="logout")
    async def logout(request: Request):
        request.session.clear()
        return RedirectResponse(
            request.url_for("show_login"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.get("/dashboard", response_class=HTMLResponse, name="dashboard")
    async def dashboard(request: Request):
        user = _get_current_user(request)
        if user is None:
            return _redirect_to_login(request)
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "user": user,
            },
        )

    @app.get("/api-key", response_class=HTMLResponse, name="api_key")
    async def api_key(request: Request):
        user = _get_current_user(request)
        if user is None:
            return _redirect_to_login(request)
        generated = request.session.pop("flash_api_key", None)
        return templates.TemplateResponse(
            "api_key.html",
            {
                "request": request,
                "user": user,
                "generated_api_key": generated,
            },
        )

    @app.post("/api-key/rotate", name="rotate_api_key")
    async def rotate_api_key(request: Request):
        user = _get_current_user(request)
        if user is None:
            return _redirect_to_login(request)
        refreshed, api_key = database.rotate_api_key(user.id)
        request.session["flash_api_key"] = api_key
        request.session["user_id"] = refreshed.id
        return RedirectResponse(
            request.url_for("api_key"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return app


__all__ = ["create_app"]
