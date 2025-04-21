# admin.py
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)
from jose import JWTError, jwt
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from schemas import AdminLogin
from db import get_db
from models import User
from passlib.context import CryptContext
from typing import List
from schemas import UserOut

from dotenv import load_dotenv

load_dotenv()

router = APIRouter()

SECRET_KEY = "your_secret"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
auth_scheme = HTTPBearer()


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def get_current_admin(
    credentials: HTTPAuthorizationCredentials = Depends(auth_scheme),
    db: Session = Depends(get_db),
):
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    admin = db.query(User).filter(User.email == email).first()
    if admin is None:
        raise credentials_exception
    return admin


def get_all_users(db: Session = Depends(get_db)):
    return


@router.post("/login", tags=["Admin"])
def admin_login(admin: AdminLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == admin.adminEmail).first()

    if db_user is None:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if db_user.role != "admin":
        raise HTTPException(status_code=403, detail="You are not authorized as admin")

    if not pwd_context.verify(admin.adminPassword, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(data={"sub": db_user.email, "role": db_user.role})
    return {"access_token": token, "token_type": "bearer"}


@router.get("/admin-dashboard", tags=["Admin"], response_model=List[UserOut])
def admin_dashboard(
    current_admin: User = Depends(get_current_admin), db: Session = Depends(get_db)
):
    if current_admin.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized as admin")

    users = db.query(User).all()
    return users


@router.delete("/admin-delete-user/{id}", tags=["Admin"])
def delete_user_by_id(
    id: int, db: Session = Depends(get_db), admin_user=Depends(get_current_admin)
):

    if admin_user:
        user = db.query(User).filter(User.id == id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        db.delete(user)
        db.commit()
        return {"message": "User deleted successfully"}
