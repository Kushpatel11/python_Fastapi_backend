from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from db import Base, engine
from auth import router as auth_router
from admin import router as admin_router
import logging

logging.basicConfig(level=logging.DEBUG)


# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

# CORS for frontend (Angular)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"message": "🚀 Hello from FastAPI"}


# Auth APIs
app.include_router(auth_router, prefix="/auth", tags=["Auth"])
app.include_router(admin_router, prefix="/admin", tags=["Admin"])
