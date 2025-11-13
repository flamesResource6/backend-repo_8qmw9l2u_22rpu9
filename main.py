import os
from datetime import datetime, date
from typing import List, Optional, Literal, Dict, Any
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents

# Environment
JWT_SECRET = os.getenv("JWT_SECRET", "secret-key-change")
JWT_ALG = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="Billing System API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helpers
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Literal['admin','staf'] = 'staf'

class AssignWilayahRequest(BaseModel):
    user_id: str
    nama_wilayah_tugas: str
    tipe_wilayah: Literal['kecamatan', 'kabupaten']

# ObjectId utils

def oid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")

# Auth utils

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_minutes: int = 60 * 10):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow().timestamp() + expires_minutes * 60})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)
    return encoded_jwt


async def get_current_user(token: str = Query(..., alias="token")):
    # token passed as query ?token=
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db["user"].find_one({"_id": oid(user_id)})
    if not user:
        raise credentials_exception
    return user


def require_role(user: dict, roles: List[str]):
    if user.get("role") not in roles:
        raise HTTPException(status_code=403, detail="Forbidden")


@app.get("/")
async def root():
    return {"message": "Billing API running"}

# Auth endpoints
@app.post("/auth/register", response_model=Dict[str, Any])
async def register(req: RegisterRequest):
    if db["user"].find_one({"email": req.email}):
        raise HTTPException(400, "Email already registered")
    user_doc = {
        "name": req.name,
        "email": req.email,
        "password_hash": get_password_hash(req.password),
        "role": req.role,
        "is_active": True,
    }
    new_id = db["user"].insert_one(user_doc).inserted_id
    return {"id": str(new_id)}


@app.post("/auth/login", response_model=Token)
async def login(req: LoginRequest):
    user = db["user"].find_one({"email": req.email})
    if not user:
        raise HTTPException(401, "Invalid credentials")
    if not verify_password(req.password, user.get("password_hash", "")):
        raise HTTPException(401, "Invalid credentials")
    token = create_access_token({"sub": str(user["_id"]), "role": user.get("role")})
    return Token(access_token=token)

# Role-based middleware-like dependencies
async def admin_user(user: dict = Depends(get_current_user)):
    require_role(user, ["admin"])
    return user

async def staf_user(user: dict = Depends(get_current_user)):
    require_role(user, ["staf", "admin"])  # admin can simulate staf endpoints
    return user

# Utility: get wilayah list for staf

def get_staf_wilayah(user_id: ObjectId):
    wilayah = list(db["stafwilayahtugas"].find({"user_id": str(user_id)}))
    return wilayah

# Admin endpoints
@app.post("/admin/users", dependencies=[Depends(admin_user)])
async def create_user(req: RegisterRequest):
    if db["user"].find_one({"email": req.email}):
        raise HTTPException(400, "Email already exists")
    user_doc = {
        "name": req.name,
        "email": req.email,
        "password_hash": get_password_hash(req.password),
        "role": req.role,
        "is_active": True,
    }
    inserted = db["user"].insert_one(user_doc)
    return {"id": str(inserted.inserted_id)}

@app.get("/admin/users", dependencies=[Depends(admin_user)])
async def list_users():
    users = list(db["user"].find())
    for u in users:
        u["id"] = str(u.pop("_id"))
        u.pop("password_hash", None)
    return users

@app.patch("/admin/users/{user_id}", dependencies=[Depends(admin_user)])
async def update_user(user_id: str, payload: dict):
    if "password" in payload:
        payload["password_hash"] = get_password_hash(payload.pop("password"))
    res = db["user"].update_one({"_id": oid(user_id)}, {"$set": payload})
    if res.matched_count == 0:
        raise HTTPException(404, "User not found")
    return {"updated": True}

@app.delete("/admin/users/{user_id}", dependencies=[Depends(admin_user)])
async def delete_user(user_id: str):
    res = db["user"].delete_one({"_id": oid(user_id)})
    if res.deleted_count == 0:
        raise HTTPException(404, "User not found")
    return {"deleted": True}

# Admin: assign wilayah CRUD
@app.post("/admin/staf-wilayah", dependencies=[Depends(admin_user)])
async def assign_wilayah(req: AssignWilayahRequest):
    if not db["user"].find_one({"_id": oid(req.user_id), "role": "staf"}):
        raise HTTPException(400, "User must be staf")
    doc = {
        "user_id": req.user_id,
        "nama_wilayah_tugas": req.nama_wilayah_tugas,
        "tipe_wilayah": req.tipe_wilayah,
    }
    inserted = db["stafwilayahtugas"].insert_one(doc)
    return {"id": str(inserted.inserted_id)}

@app.get("/admin/staf-wilayah/{user_id}", dependencies=[Depends(admin_user)])
async def list_wilayah(user_id: str):
    wilayah = list(db["stafwilayahtugas"].find({"user_id": user_id}))
    for w in wilayah:
        w["id"] = str(w.pop("_id"))
    return wilayah

@app.delete("/admin/staf-wilayah/{id}", dependencies=[Depends(admin_user)])
async def delete_wilayah(id: str):
    res = db["stafwilayahtugas"].delete_one({"_id": oid(id)})
    if res.deleted_count == 0:
        raise HTTPException(404, "Not found")
    return {"deleted": True}

# Master data: golongan & tarif progresif
@app.post("/admin/golongan", dependencies=[Depends(admin_user)])
async def create_golongan(payload: dict):
    if db["golongan"].find_one({"kode_golongan": payload.get("kode_golongan")}):
        raise HTTPException(400, "Kode golongan exists")
    inserted = db["golongan"].insert_one(payload)
    return {"id": str(inserted.inserted_id)}

@app.get("/admin/golongan", dependencies=[Depends(admin_user)])
async def list_golongan():
    data = list(db["golongan"].find())
    for d in data:
        d["id"] = str(d.pop("_id"))
    return data

@app.post("/admin/tarif-progresif", dependencies=[Depends(admin_user)])
async def create_tarif(payload: dict):
    inserted = db["tarifprogresif"].insert_one(payload)
    return {"id": str(inserted.inserted_id)}

@app.get("/admin/tarif-progresif/{id_golongan}", dependencies=[Depends(admin_user)])
async def list_tarif(id_golongan: str):
    tiers = list(db["tarifprogresif"].find({"id_golongan": id_golongan}).sort("batas_bawah_m3", 1))
    for t in tiers:
        t["id"] = str(t.pop("_id"))
    return tiers

# Pelanggan CRUD (admin full access)
@app.post("/admin/pelanggan", dependencies=[Depends(admin_user)])
async def create_pelanggan(payload: dict):
    if db["pelanggan"].find_one({"nomor_pelanggan": payload.get("nomor_pelanggan")}):
        raise HTTPException(400, "Nomor pelanggan exists")
    inserted = db["pelanggan"].insert_one(payload)
    return {"id": str(inserted.inserted_id)}

@app.get("/admin/pelanggan", dependencies=[Depends(admin_user)])
async def list_pelanggan_admin(q: Optional[str] = None):
    filt = {}
    if q:
        filt = {"$or": [
            {"nomor_pelanggan": {"$regex": q, "$options": "i"}},
            {"nama_pelanggan": {"$regex": q, "$options": "i"}},
        ]}
    data = list(db["pelanggan"].find(filt))
    for d in data:
        d["id"] = str(d.pop("_id"))
    return data

@app.patch("/admin/pelanggan/{id}", dependencies=[Depends(admin_user)])
async def update_pelanggan_admin(id: str, payload: dict):
    res = db["pelanggan"].update_one({"_id": oid(id)}, {"$set": payload})
    if res.matched_count == 0:
        raise HTTPException(404, "Not found")
    return {"updated": True}

# Tagihan admin
@app.get("/admin/tagihan", dependencies=[Depends(admin_user)])
async def list_tagihan_admin(q: Optional[str] = None):
    # q can be nomor_nota or nomor_pelanggan
    filt = {}
    if q:
        pelanggan = list(db["pelanggan"].find({"nomor_pelanggan": {"$regex": q, "$options": "i"}}))
        pelanggan_ids = [p["_id"] for p in pelanggan]
        filt = {"$or": [
            {"nomor_nota": {"$regex": q, "$options": "i"}},
            {"id_pelanggan": {"$in": [str(_id) for _id in pelanggan_ids]}},
        ]}
    data = list(db["tagihan"].find(filt).sort("tanggal_tagihan", -1))
    for d in data:
        d["id"] = str(d.pop("_id"))
    return data

@app.patch("/admin/tagihan/{id}", dependencies=[Depends(admin_user)])
async def update_tagihan_admin(id: str, payload: dict):
    res = db["tagihan"].update_one({"_id": oid(id)}, {"$set": payload})
    if res.matched_count == 0:
        raise HTTPException(404, "Not found")
    return {"updated": True}

@app.delete("/admin/tagihan/{id}", dependencies=[Depends(admin_user)])
async def delete_tagihan_admin(id: str):
    res = db["tagihan"].delete_one({"_id": oid(id)})
    if res.deleted_count == 0:
        raise HTTPException(404, "Not found")
    db["detailtagihan"].delete_many({"id_tagihan": id})
    db["pembayaran"].delete_many({"id_tagihan": id})
    return {"deleted": True}

# Staff-limited filters

def staff_filter_for_pelanggan(user: dict) -> dict:
    wilayah = get_staf_wilayah(user["_id"])
    if not wilayah:
        return {"_id": {"$exists": False}}  # no access
    ors = []
    for w in wilayah:
        if w.get("tipe_wilayah") == "kecamatan":
            ors.append({"kecamatan": w.get("nama_wilayah_tugas")})
        else:
            ors.append({"kabupaten": w.get("nama_wilayah_tugas")})
    return {"$or": ors}

# Pelanggan endpoints (staf)
@app.get("/staf/pelanggan", dependencies=[Depends(staf_user)])
async def list_pelanggan_staf(q: Optional[str] = None, user: dict = Depends(get_current_user)):
    base = staff_filter_for_pelanggan(user)
    if q:
        base = {"$and": [base, {"$or": [
            {"nomor_pelanggan": {"$regex": q, "$options": "i"}},
            {"nama_pelanggan": {"$regex": q, "$options": "i"}},
        ]}]}
    data = list(db["pelanggan"].find(base))
    for d in data:
        d["id"] = str(d.pop("_id"))
    return data

@app.post("/staf/pelanggan", dependencies=[Depends(staf_user)])
async def create_pelanggan_staf(payload: dict, user: dict = Depends(get_current_user)):
    # ensure wilayah allowed
    base = staff_filter_for_pelanggan(user)
    # Only allowed if payload wilayah matches any
    allowed = False
    for cond in base.get("$or", []):
        for key, val in cond.items():
            if payload.get(key) == val:
                allowed = True
    if not allowed:
        raise HTTPException(403, "Wilayah tidak diizinkan")
    if db["pelanggan"].find_one({"nomor_pelanggan": payload.get("nomor_pelanggan")}):
        raise HTTPException(400, "Nomor pelanggan exists")
    inserted = db["pelanggan"].insert_one(payload)
    return {"id": str(inserted.inserted_id)}

@app.patch("/staf/pelanggan/{id}", dependencies=[Depends(staf_user)])
async def update_pelanggan_staf(id: str, payload: dict, user: dict = Depends(get_current_user)):
    base = staff_filter_for_pelanggan(user)
    # ensure the pelanggan is within base
    pel = db["pelanggan"].find_one({"$and": [{"_id": oid(id)}, base]})
    if not pel:
        raise HTTPException(403, "Akses ditolak")
    res = db["pelanggan"].update_one({"_id": oid(id)}, {"$set": payload})
    return {"updated": res.modified_count > 0}

# Utility: get last meter akhir for a pelanggan and periode

def get_last_meter_akhir(id_pelanggan: str, periode: str) -> int:
    # retrieve latest previous periode's meter_akhir
    doc = db["tagihan"].find_one({"id_pelanggan": id_pelanggan, "periode_tagihan": {"$lt": periode}}, sort=[("periode_tagihan", -1)])
    if not doc:
        return 0
    return int(doc.get("meter_akhir", 0))

# Pricing calculation

def hitung_total_harga_air(id_golongan: str, pemakaian: int):
    tiers = list(db["tarifprogresif"].find({"id_golongan": id_golongan}).sort("batas_bawah_m3", 1))
    sisa = pemakaian
    total = 0.0
    detail: List[dict] = []
    for t in tiers:
        lower = int(t.get("batas_bawah_m3", 0))
        upper = int(t.get("batas_atas_m3", 0))
        harga = float(t.get("harga_per_m3", 0))
        if sisa <= 0:
            break
        # range size for this tier
        kapasitas = max(0, upper - lower + 1)
        pakai = min(sisa, kapasitas)
        subtotal = pakai * harga
        total += subtotal
        detail.append({
            "keterangan_tier": f"{lower}-{upper}",
            "pakai_m3": pakai,
            "harga_per_m3": harga,
            "subtotal": subtotal,
        })
        sisa -= pakai
    # if pemakaian melebihi last upper, charge last tier price
    if sisa > 0 and tiers:
        last = tiers[-1]
        harga = float(last.get("harga_per_m3", 0))
        subtotal = sisa * harga
        total += subtotal
        detail.append({
            "keterangan_tier": f">{last.get('batas_atas_m3')}",
            "pakai_m3": sisa,
            "harga_per_m3": harga,
            "subtotal": subtotal,
        })
    return total, detail

# Staf: Pencatatan meter -> create tagihan
class CatatMeterRequest(BaseModel):
    id_pelanggan: str
    periode_tagihan: str  # YYYY-MM
    meter_akhir: int

@app.post("/staf/catat-meter", dependencies=[Depends(staf_user)])
async def catat_meter(req: CatatMeterRequest, user: dict = Depends(get_current_user)):
    # ensure pelanggan in wilayah
    pel = db["pelanggan"].find_one({"_id": oid(req.id_pelanggan)})
    if not pel:
        raise HTTPException(404, "Pelanggan tidak ditemukan")
    # wilayah check
    base = staff_filter_for_pelanggan(user)
    allow = db["pelanggan"].find_one({"$and": [{"_id": oid(req.id_pelanggan)}, base]})
    if not allow:
        raise HTTPException(403, "Akses wilayah ditolak")

    meter_awal = get_last_meter_akhir(req.id_pelanggan, req.periode_tagihan)
    pemakaian = max(0, req.meter_akhir - meter_awal)

    # get golongan
    id_gol = pel.get("id_golongan")
    total_harga, detail = hitung_total_harga_air(id_gol, pemakaian)

    gol = db["golongan"].find_one({"_id": oid(id_gol)})
    biaya_beban = float(gol.get("biaya_beban", 0)) if gol else 0.0

    total_tagihan = total_harga + biaya_beban

    tagihan_doc = {
        "nomor_nota": f"NT-{int(datetime.utcnow().timestamp())}",
        "id_pelanggan": req.id_pelanggan,
        "periode_tagihan": req.periode_tagihan,
        "tanggal_tagihan": datetime.utcnow().date().isoformat(),
        "meter_awal": meter_awal,
        "meter_akhir": req.meter_akhir,
        "pemakaian_m3": pemakaian,
        "total_harga_air": total_harga,
        "biaya_beban": biaya_beban,
        "denda": 0.0,
        "total_tagihan": total_tagihan,
        "status_bayar": "Belum Bayar",
        "id_petugas_catat": str(user["_id"]) ,
    }
    tagihan_id = db["tagihan"].insert_one(tagihan_doc).inserted_id

    for d in detail:
        d.update({"id_tagihan": str(tagihan_id)})
        db["detailtagihan"].insert_one(d)

    return {"id": str(tagihan_id)}

# Staf: daftar tagihan (wilayah terbatas)
@app.get("/staf/tagihan", dependencies=[Depends(staf_user)])
async def list_tagihan_staf(q: Optional[str] = None, user: dict = Depends(get_current_user)):
    base = staff_filter_for_pelanggan(user)
    # find pelanggan in wilayah
    pel_ids = [str(p["_id"]) for p in db["pelanggan"].find(base, {"_id": 1})]
    filt: Dict[str, Any] = {"id_pelanggan": {"$in": pel_ids}}
    if q:
        filt = {"$and": [filt, {"$or": [
            {"nomor_nota": {"$regex": q, "$options": "i"}},
            {"id_pelanggan": {"$in": [str(p["_id"]) for p in db["pelanggan"].find({"nomor_pelanggan": {"$regex": q, "$options": "i"}}, {"_id": 1})]}},
        ]}]}
    data = list(db["tagihan"].find(filt).sort("tanggal_tagihan", -1))
    for d in data:
        d["id"] = str(d.pop("_id"))
    return data

# Pembayaran (staf wilayah)
class BayarRequest(BaseModel):
    id_tagihan: str
    jumlah_bayar: float
    metode_bayar: str

@app.post("/staf/bayar", dependencies=[Depends(staf_user)])
async def proses_bayar(req: BayarRequest, user: dict = Depends(get_current_user)):
    tagihan = db["tagihan"].find_one({"_id": oid(req.id_tagihan)})
    if not tagihan:
        raise HTTPException(404, "Tagihan tidak ditemukan")
    # wilayah check via pelanggan
    pel = db["pelanggan"].find_one({"_id": oid(tagihan.get("id_pelanggan"))})
    if not pel:
        raise HTTPException(404, "Pelanggan tidak ditemukan")
    base = staff_filter_for_pelanggan(user)
    allow = db["pelanggan"].find_one({"$and": [{"_id": oid(pel["_id"])} , base]})
    if not allow:
        raise HTTPException(403, "Akses wilayah ditolak")

    if tagihan.get("status_bayar") == "Lunas":
        raise HTTPException(400, "Tagihan sudah lunas")

    db["pembayaran"].insert_one({
        "id_tagihan": req.id_tagihan,
        "tanggal_bayar": datetime.utcnow().isoformat(),
        "jumlah_bayar": req.jumlah_bayar,
        "metode_bayar": req.metode_bayar,
        "id_kasir": str(user["_id"]) ,
    })
    db["tagihan"].update_one({"_id": oid(req.id_tagihan)}, {"$set": {"status_bayar": "Lunas"}})
    return {"status": "OK"}

# Dashboard summaries
@app.get("/dashboard/admin", dependencies=[Depends(admin_user)])
async def dashboard_admin():
    total_pelanggan = db["pelanggan"].count_documents({})
    total_tagihan = db["tagihan"].count_documents({})
    total_lunas = db["tagihan"].count_documents({"status_bayar": "Lunas"})
    # sum pendapatan
    pendapatan = 0.0
    for p in db["pembayaran"].find():
        pendapatan += float(p.get("jumlah_bayar", 0))
    return {
        "total_pelanggan": total_pelanggan,
        "total_tagihan": total_tagihan,
        "tagihan_lunas": total_lunas,
        "total_pendapatan": pendapatan,
    }

@app.get("/dashboard/staf", dependencies=[Depends(staf_user)])
async def dashboard_staf(user: dict = Depends(get_current_user)):
    base = staff_filter_for_pelanggan(user)
    pel_ids = [str(p["_id"]) for p in db["pelanggan"].find(base, {"_id": 1})]
    total_pelanggan = len(pel_ids)
    total_tagihan = db["tagihan"].count_documents({"id_pelanggan": {"$in": pel_ids}})
    total_belum = db["tagihan"].count_documents({"id_pelanggan": {"$in": pel_ids}, "status_bayar": "Belum Bayar"})
    return {
        "pelanggan_wilayah": total_pelanggan,
        "tagihan_wilayah": total_tagihan,
        "tagihan_belum_lunas": total_belum,
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
