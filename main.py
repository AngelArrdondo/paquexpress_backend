from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Numeric
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import shutil
import os

# ------------------------------
# CONFIGURACIÓN GENERAL
# ------------------------------

JWT_SECRET = "3d414325104696e6bb0e7e63bf2668e31c5ad96a823f0a38959e96fa620cf49c"
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_MIN = 60 * 24  # 1 día

DATABASE_URL = "mysql+pymysql://root:Angel2006%40@localhost:3306/paquexpress"

# ------------------------------
# CONEXIÓN A BD
# ------------------------------

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ------------------------------
# MODELOS SQLALCHEMY
# ------------------------------

class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, index=True)
    nombre = Column(String(150))
    password_hash = Column(String(255))
    rol = Column(String(50))
    creado_at = Column(DateTime, default=datetime.utcnow)

    paquetes = relationship("Paquete", back_populates="agente")


class Paquete(Base):
    __tablename__ = "paquetes"

    id = Column(Integer, primary_key=True)
    paquete_id = Column(String(100), index=True)
    direccion = Column(String(255))
    ciudad = Column(String(100))
    estado = Column(String(100))
    codigo_postal = Column(String(20))
    destinatario = Column(String(150))
    asignado_a = Column(Integer, ForeignKey("usuarios.id"))
    estado_entrega = Column(String(50), default="pendiente")
    creado_at = Column(DateTime, default=datetime.utcnow)

    agente = relationship("Usuario", back_populates="paquetes")
    entregas = relationship("Entrega", back_populates="paquete")


class Entrega(Base):
    __tablename__ = "entregas"

    id = Column(Integer, primary_key=True)
    paquete_id = Column(Integer, ForeignKey("paquetes.id"))
    agente_id = Column(Integer, ForeignKey("usuarios.id"))
    lat = Column(Numeric(10, 7), nullable=True)
    lon = Column(Numeric(10, 7), nullable=True)
    foto_path = Column(String(255))
    timestamp = Column(DateTime, default=datetime.utcnow)

    paquete = relationship("Paquete", back_populates="entregas")


Base.metadata.create_all(bind=engine)

# ----------------------------------------
# Pydantic Schemas
# ----------------------------------------

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class PaqueteSchema(BaseModel):
    id: int
    paquete_id: str
    direccion: str
    ciudad: str
    estado: str
    codigo_postal: str
    destinatario: str
    estado_entrega: str

    model_config = {"from_attributes": True}

# ----------------------------------------
# Seguridad
# ----------------------------------------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MIN)
    to_encode["exp"] = int(expire.timestamp())
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_user_from_token(token: str, db: Session):
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = decoded.get("sub")
        if not username:
            return None
    except Exception:
        return None

    return db.query(Usuario).filter(Usuario.username == username).first()

# ----------------------------------------
# FastAPI Init
# ----------------------------------------

app = FastAPI(title="Paquexpress Agente API")

os.makedirs("uploads", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ----------------------------------------
# ENDPOINTS
# ----------------------------------------

@app.post("/login", response_model=Token)
def login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(Usuario).filter(Usuario.username == username).first()

    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    token = create_token({"sub": user.username, "user_id": user.id})
    return {"access_token": token}


@app.get("/paquetes", response_model=list[PaqueteSchema])
def obtener_paquetes(authorization: str = Header(None), db: Session = Depends(get_db)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Falta token")

    _, _, token = authorization.partition(" ")
    user = get_user_from_token(token, db)

    if not user:
        raise HTTPException(status_code=401, detail="Token inválido")

    paquetes = db.query(Paquete).filter(
        Paquete.asignado_a == user.id,
        Paquete.estado_entrega == "pendiente"
    ).all()

    return [PaqueteSchema.model_validate(p) for p in paquetes]


# ----------------------------------------
# CORRECCIÓN COMPLETA → Guardar .jpg / .png
# ----------------------------------------

@app.post("/entregar")
async def entregar_paquete(
    paquete_id: int = Form(...),
    lat: float | None = Form(None),
    lon: float | None = Form(None),
    file: UploadFile = File(...),
    authorization: str = Header(None),
    db: Session = Depends(get_db)
):
    if not authorization:
        raise HTTPException(status_code=401, detail="Falta token")

    _, _, token = authorization.partition(" ")
    user = get_user_from_token(token, db)

    if not user:
        raise HTTPException(status_code=401, detail="Token inválido")

    paquete = db.query(Paquete).filter(Paquete.id == paquete_id).first()

    if not paquete:
        raise HTTPException(status_code=404, detail="Paquete no encontrado")

    if paquete.estado_entrega == "entregado":
        raise HTTPException(status_code=400, detail="Este paquete ya fue entregado")

    # ---------------------------
    # CORRECCIÓN: detectar tipo y asignar extensión
    # ---------------------------

    if file.content_type == "image/png":
        ext = ".png"
    elif file.content_type in ["image/jpeg", "image/jpg"]:
        ext = ".jpg"
    else:
        raise HTTPException(status_code=400, detail="Tipo de archivo no permitido (solo JPG o PNG)")

    filename = f"{user.id}_{paquete_id}_{int(datetime.utcnow().timestamp())}{ext}"
    path = os.path.join("uploads", filename)

    # Guardar archivo
    try:
        with open(path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al guardar la imagen: {e}")

    # Registrar entrega
    try:
        entrega = Entrega(
            paquete_id=paquete_id,
            agente_id=user.id,
            lat=lat,
            lon=lon,
            foto_path=path
        )

        db.add(entrega)
        paquete.estado_entrega = "entregado"

        db.commit()
        db.refresh(entrega)

    except Exception as e:
        db.rollback()
        if os.path.exists(path):
            os.remove(path)
        raise HTTPException(status_code=500, detail=f"Error DB: {e}")

    return {"mensaje": "Entrega registrada", "foto": path, "entrega_id": entrega.id}

