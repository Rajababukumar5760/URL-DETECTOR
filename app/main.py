from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from app.schemas import AnalyzeRequest, AnalyzeResponse
from app.url_analyzer import analyze_url, URLAnalysisError, MAX_URL_LENGTH
from app.risk_engine import evaluate_rules
from app.ml_model import predict, model_status

BASE_DIR = Path(__file__).resolve().parent
app = FastAPI(title="PhishGuard API", version="1.0.0", description="Explainable offline URL risk assessment. Submitted URLs are not visited.")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": "Invalid request. Provide a non-empty URL no longer than 4096 characters."})

@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": str(exc.detail)})

@app.get("/health")
def health():
    return {"status": "ok", "service": "PhishGuard", "ml_model": model_status()["status"]}

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={"request": request})

@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest):
    try:
        features = analyze_url(payload.url)
    except URLAnalysisError as exc:
        return JSONResponse(status_code=422, content={"detail": str(exc)})
    rules = evaluate_rules(features)
    ml = predict(features)
    precautions = [
        "Do not enter passwords, payment details, or one-time codes on a site you do not trust.",
        "Check the exact hostname carefully; do not rely on the logo or page appearance.",
        "Open the known official website using a bookmark or trusted search result instead of a suspicious link.",
        "If this link came in an unexpected message, verify with the sender through a separate channel.",
    ]
    return {"valid": True, "normalized_url": features["normalized_url"], "hostname": features["hostname"],
            "features": {k: v for k, v in features.items() if k not in {"raw_url", "normalized_url", "hostname_unicode", "path", "registrable_domain_note"}},
            "findings": rules["findings"], "rule_score": rules["rule_score"], "risk_category": rules["risk_category"],
            "explanation": rules["explanation"], "precautions": precautions, "ml": ml,
            "threat_intelligence": {"checked": False, "status": "not_configured", "message": "No external threat-intelligence service was queried."}}
