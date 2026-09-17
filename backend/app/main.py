from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from contextlib import asynccontextmanager

# Verification router addition for SIH26106 P4
from app.api.routes import analysis, auth, batch_analysis, cases, dashboard, health, indicators, live_threats, threats, admin, password, google_auth, simulate, iocs, audit, inbox, verification, evidence, investigation, intelligence
from app.core.config import settings
from app.database import init_db
from app.realtime import alert_manager
from app.detection.ml_classifier import get_ml_classifier

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Eager load the ML model to prevent cold start on first scan
    get_ml_classifier()
    yield


app = FastAPI(title=settings.APP_NAME, version="0.1.0", debug=settings.DEBUG, lifespan=lifespan)

if settings.JWT_SECRET:
    app.add_middleware(SessionMiddleware, secret_key=settings.JWT_SECRET, same_site="lax", https_only=False)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)





app.include_router(health.router, prefix="/api")
app.include_router(auth.router, prefix="/api")
app.include_router(threats.router, prefix="/api")
app.include_router(indicators.router, prefix="/api")
app.include_router(live_threats.router, prefix="/api")
app.include_router(analysis.router, prefix="/api")
app.include_router(batch_analysis.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(cases.router, prefix="/api")
app.include_router(admin.router, prefix="/api")
app.include_router(password.router, prefix="/api")
app.include_router(google_auth.router, prefix="/api")
app.include_router(simulate.router, prefix="/api")
app.include_router(iocs.router, prefix="/api")
app.include_router(audit.router, prefix="/api")
app.include_router(inbox.router, prefix="/api")
app.include_router(verification.router)
app.include_router(evidence.router)
app.include_router(investigation.router)
app.include_router(intelligence.router)


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await alert_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        alert_manager.disconnect(websocket)
