
# StashFund Backend — FastAPI + SQLite/Postgres + Bank Linking Stub + Owner Backdoor
# Railway-ready version (uses DATABASE_URL + env vars for secrets)

import os, time
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlmodel import Field, SQLModel, Session, create_engine, select

# -------------------------- Config --------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "super_secret_key_change_me")
JWT_ALG = "HS256"
ACCESS_MIN = int(os.getenv("ACCESS_MIN_MINUTES", "120"))

# DB_URL: use Railway DATABASE_URL (Postgres) or fallback to SQLite
DB_URL = os.getenv("DATABASE_URL", "sqlite:///./stashfund.db")
connect_args = {}
if DB_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
engine = create_engine(DB_URL, echo=False, connect_args=connect_args)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Owner credentials from env vars
OWNER_EMAIL = os.getenv("OWNER_EMAIL", "adisaishree@gmail.com")
OWNER_ACCESS_CODE = os.getenv("OWNER_ACCESS_CODE", "12345678")

# -------------------------- Models --------------------------
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    full_name: str
    password_hash: str
    role: str = "USER"
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Transaction(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(index=True)
    date: datetime
    amount: float
    description: str
    category: str
    is_income: bool = False

class SavingsGoal(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int
    name: str
    target_amount: float
    current_amount: float = 0.0
    target_date: datetime

class ExpenseBudget(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int
    category: str
    monthly_limit: float
    month: int
    year: int

class BankLink(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int
    provider: str = "AA_STUB"
    masked_acct: str
    status: str = "active"
    created_at: datetime = Field(default_factory=datetime.utcnow)

# -------------------------- Schemas --------------------------
class RegisterIn(BaseModel):
    email: str
    password: str
    full_name: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TxIn(BaseModel):
    date: datetime
    amount: float
    description: str
    is_income: bool = False
    category: Optional[str] = None

class SavingsIn(BaseModel):
    name: str
    target_amount: float
    current_amount: float = 0.0
    target_date: datetime

class BudgetIn(BaseModel):
    category: str
    monthly_limit: float
    month: int
    year: int

# -------------------------- Helpers --------------------------
def hash_pw(p: str) -> str: return pwd_context.hash(p)
def verify_pw(p: str, h: str) -> bool: return pwd_context.verify(p, h)
def create_access_token(sub: int, role: str) -> str:
    return jwt.encode(
        {"sub": str(sub), "role": role, "exp": datetime.utcnow() + timedelta(minutes=ACCESS_MIN)},
        JWT_SECRET, algorithm=JWT_ALG)

def get_db():
    with Session(engine) as s: yield s

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        sub = int(jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG]).get("sub"))
    except JWTError:
        raise HTTPException(401, "Invalid token")
    u = db.get(User, sub)
    if not u: raise HTTPException(401, "User not found")
    return u

def require_owner(email: str, access_code: str):
    if email != OWNER_EMAIL or access_code != OWNER_ACCESS_CODE:
        raise HTTPException(403, "Forbidden: Invalid owner credentials")
    return True

# -------------------------- App --------------------------
app = FastAPI(title="StashFund API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
SQLModel.metadata.create_all(engine)

# -------------------------- Auth --------------------------
@app.post("/auth/register", response_model=TokenOut)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    if db.exec(select(User).where(User.email == data.email)).first():
        raise HTTPException(409, "Email exists")
    u = User(email=data.email, full_name=data.full_name, password_hash=hash_pw(data.password))
    db.add(u); db.commit(); db.refresh(u)
    return TokenOut(access_token=create_access_token(u.id, u.role))

@app.post("/auth/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    u = db.exec(select(User).where(User.email == form.username)).first()
    if not u or not verify_pw(form.password, u.password_hash): raise HTTPException(401, "Bad credentials")
    return TokenOut(access_token=create_access_token(u.id, u.role))

# -------------------------- Bank Linking (Stub) --------------------------
@app.post("/banks/link/start")
def bank_link_start(user: User = Depends(get_current_user)):
    return {"ok": True, "data": {"linkToken": f"stub-{user.id}-{int(time.time())}"}}

@app.post("/banks/link/finish")
def bank_link_finish(payload: dict, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    link = BankLink(user_id=user.id, masked_acct="XXXX-1234")
    db.add(link); db.commit(); db.refresh(link)
    return {"ok": True, "data": link}

@app.get("/banks/accounts")
def bank_accounts(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return {"ok": True, "data": db.exec(select(BankLink).where(BankLink.user_id == user.id)).all()}

# -------------------------- Owner Backdoor --------------------------
@app.get("/owner/users")
def owner_users(email: str, access_code: str, db: Session = Depends(get_db)):
    require_owner(email, access_code)
    return {"ok": True, "data": db.exec(select(User)).all()}

@app.get("/owner/user/{uid}")
def owner_user(uid: int, email: str, access_code: str, db: Session = Depends(get_db)):
    require_owner(email, access_code)
    u = db.get(User, uid)
    if not u: raise HTTPException(404, "User not found")
    tx = db.exec(select(Transaction).where(Transaction.user_id == uid)).all()
    goals = db.exec(select(SavingsGoal).where(SavingsGoal.user_id == uid)).all()
    budgets = db.exec(select(ExpenseBudget).where(ExpenseBudget.user_id == uid)).all()
    banks = db.exec(select(BankLink).where(BankLink.user_id == uid)).all()
    return {"ok": True, "data": {"user": u, "transactions": tx, "goals": goals, "budgets": budgets, "banks": banks}}

# -------------------------- Health --------------------------
@app.get("/health")
def health(): return {"ok": True, "ts": datetime.utcnow().isoformat()}
