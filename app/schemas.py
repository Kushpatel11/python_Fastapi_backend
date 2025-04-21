from pydantic import BaseModel, EmailStr
from typing import Optional


class UserCreate(BaseModel):
    firstname: str
    lastname: str
    email: EmailStr
    password: str
    mobile: Optional[str] = None


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: int
    firstname: str
    lastname: str
    email: EmailStr
    mobile: Optional[str]

    class Config:
        from_attributes = True


class UserUpdate(BaseModel):
    firstname: Optional[str] = None
    lastname: Optional[str] = None
    email: Optional[EmailStr] = None
    mobile: Optional[str] = None


class TokenData(BaseModel):
    email: str
