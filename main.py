from fastapi import FastAPI
from fastapi.responses import ORJSONResponse
from fastapi.staticfiles import StaticFiles  # Dodaj ovo

from src.routers import router


app = FastAPI(default_response_class=ORJSONResponse)
app.mount("/", StaticFiles(directory="frontend", html=True), name="static")
app.include_router(router)
