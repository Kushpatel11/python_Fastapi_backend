# admin.py
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPAuthorizationCredentials, OAuth2PasswordRequestForm,HTTPBearer
from jose import jwt,JWTError
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from db import get_db
from models import User

router = APIRouter( )

SECRET_KEY = "your_secret"
ALGORITHM = "HS256"

ADMIN_EMAIL = "admin@demo.com"
ADMIN_PASSWORD = "admin123"


auth_scheme = HTTPBearer()


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_admin_token(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)) -> str:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email != ADMIN_EMAIL:
            raise HTTPException(status_code=403, detail="Not authorized")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@router.post("/login", tags=["Admin"])
def admin_login(form_data: OAuth2PasswordRequestForm = Depends()):


    if form_data.username != ADMIN_EMAIL or form_data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": form_data.username})
    return {"access_token": token, "token_type": "bearer"}


@router.get("/users", tags=["Admin"])
def get_all_users(
    admin_email: str = Depends(verify_admin_token),
    db: Session = Depends(get_db)
):
    users = db.query(User).all()
    return {
        "admin": admin_email,
        "users": [
    {
        "id": user.id,
        "firstname": user.firstname,
        "lastname": user.lastname,
        "email": user.email,
        "mobile": user.mobile
    }
    for user in users
]
    }


@router.delete("/users/{user_id}", tags=["Admin"])
def delete_user_by_id(
    user_id: int,
    admin_email: str = Depends(verify_admin_token),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()

    return {"message": f"User with ID {user_id} deleted successfully"}