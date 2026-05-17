from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from database.db import engine, Base
from api.routes import router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Setup - Startup
    logger.info("Initializing database and tables on startup...")
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Critical error initializing database: {e}")
    yield
    # Teardown - Shutdown
    logger.info("Shutting down API Service...")

app = FastAPI(
    title="Phishing Email Detection & Investigation Platform",
    description="Automated SOC Blue-Team system designed for email analysis, risk scoring, threat intelligence enrichment, and case workflows.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Configuration - allow access from Next.js frontend dev port 3000 and standard client origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Router
app.include_router(router, prefix="/api")

@app.get("/")
def get_status():
    return {
        "status": "online",
        "service": "Phishing Detection & Investigation API",
        "version": "1.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    # In development, run local dev server
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
