from pydantic import BaseModel, Field

class PasswordResetRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)
