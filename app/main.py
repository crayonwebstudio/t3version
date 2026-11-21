"""t3version: identify a TYPO3 version from a public URL.

Web UI with session login, JSON API with X-API-Key auth.
All secrets come from environment variables only:
  ADMIN_USER, ADMIN_PASSWORD, SECRET_KEY, API_TOKEN
"""
import hmac
import os

from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .detector import detect, hash_db_versions

ADMIN_USER = os.environ.get("ADMIN_USER", "milan")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me")
API_TOKEN = os.environ.get("API_TOKEN", "")

app = FastAPI(title="t3version", docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY,
                   same_site="lax", https_only=False)
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))


def _signed_in(request: Request) -> bool:
    return bool(request.session.get("user"))


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if _signed_in(request):
        return RedirectResponse("/dashboard", status_code=302)
    return RedirectResponse("/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": ""})


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ok_user = hmac.compare_digest(username, ADMIN_USER)
    ok_pass = ADMIN_PASSWORD and hmac.compare_digest(password, ADMIN_PASSWORD)
    if ok_user and ok_pass:
        request.session["user"] = username
        return RedirectResponse("/dashboard", status_code=302)
    return templates.TemplateResponse(
        "login.html", {"request": request, "error": "Wrong username or password."},
        status_code=401)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    if not _signed_in(request):
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "user": request.session.get("user"),
         "versions": hash_db_versions(), "result": None, "checked_url": ""})


@app.post("/check", response_class=HTMLResponse)
def check_form(request: Request, url: str = Form(...)):
    if not _signed_in(request):
        return RedirectResponse("/login", status_code=302)
    result = detect(url)
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "user": request.session.get("user"),
         "versions": hash_db_versions(), "result": result, "checked_url": url})


@app.post("/api/v1/check")
def api_check(payload: dict, x_api_key: str = Header(default="")):
    if not API_TOKEN or not hmac.compare_digest(x_api_key, API_TOKEN):
        raise HTTPException(status_code=401, detail="invalid API key")
    url = (payload or {}).get("url", "")
    if not url:
        raise HTTPException(status_code=400, detail="url is required")
    result = detect(url)
    return JSONResponse(result)
