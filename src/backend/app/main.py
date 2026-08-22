from fastapi import FastAPI
from app.routes.auth_routes import router as auth_router
from fastapi.middlware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins = ["*"],
    allow_creadentials =True,
    allow_methods = ["*"],
    allow_headers = ["*"],
    )

app.include_router(auth_router)
