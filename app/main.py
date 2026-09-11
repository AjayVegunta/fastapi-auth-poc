from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, EmailStr

from .auth import authenticate_user, create_access_token, hash_password
from .db import (
    create_user,
    get_audit_logs,
    get_user_by_email,
    init_db,
    write_audit_log,
)
app = FastAPI(
    title="Incident Debugging Auth POC",
    version="0.1.0",
)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/register")
def register(data: RegisterRequest):
    existing_user = get_user_by_email(data.email)

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="User already exists",
        )

    user_id = create_user(
        data.email,
        hash_password(data.password),
    )

    return {
        "user_id": user_id,
        "email": data.email,
        "message": "User registered successfully",
    }

@app.post("/login")
def login(
    data: LoginRequest,
    request: Request,
):
    request_id = request.headers.get("X-Request-ID") or "local-test"

    user = authenticate_user(
        data.email,
        data.password,
    )

    if not user:
        write_audit_log(
            event_type="login",
            email=data.email,
            user_id=None,
            success=False,
            status_code=401,
            request_id=request_id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            message="Invalid credentials",
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )

    access_token = create_access_token(
        user["id"],
        user["email"],
    )

    write_audit_log(
        event_type="login",
        email=data.email,
        user_id=user["id"],
        success=True,
        status_code=200,
        request_id=request_id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        message="Login successful",
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }
    
@app.get("/audit-logs")
def audit_logs(limit: int = 100):
    return {
        "items": get_audit_logs(limit),
    }