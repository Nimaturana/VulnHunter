from fastapi import APIRouter

from vulnhunter.scans.routes import router as scans_router
from vulnhunter.system.routes import router as system_router

api_router = APIRouter()
api_router.include_router(system_router)
api_router.include_router(scans_router)
