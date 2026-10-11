from fastapi import FastAPI
from _security.routers import router
from fastapi.middleware.cors import CORSMiddleware
import dotenv
import config

dotenv.load_dotenv()
  

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins= config.settings.CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)
app.include_router(router)