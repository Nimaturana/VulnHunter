from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl


class WebsiteCreate(BaseModel):
    url: HttpUrl


class WebsiteVerifyRequest(BaseModel):
    method: str = Field(pattern="^(http_file|dns_txt)$")
    token: str = Field(min_length=20, max_length=200)


class WebsiteResponse(BaseModel):
    id: int
    url: str
    user_id: int
    verification_status: str
    verification_method: str | None
    verification_token_expires_at: datetime | None
    verified_at: datetime | None
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class VerificationChallenge(BaseModel):
    website: WebsiteResponse
    token: str
    http_file_url: str
    dns_record_name: str
    dns_record_value: str
    explanation: str

