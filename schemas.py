"""
Database Schemas for Billing System

Each Pydantic model corresponds to a MongoDB collection. Collection name is the lowercase class name.

Collections:
- User (role-based access)
- StafWilayahTugas (mapping staff to wilayah)
- Golongan (tariff group)
- TarifProgresif (progressive tiers per golongan)
- Pelanggan (customers)
- Tagihan (bills)
- DetailTagihan (bill line items for tiers)
- Pembayaran (payments)
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal, List
from datetime import date, datetime

Role = Literal['admin', 'staf']
StatusPelanggan = Literal['Aktif', 'Nonaktif']
StatusBayar = Literal['Belum Bayar', 'Lunas']
TipeWilayah = Literal['kecamatan', 'kabupaten']

class User(BaseModel):
    name: str = Field(..., description="Nama lengkap")
    email: EmailStr = Field(..., description="Email unik")
    password_hash: str = Field(..., description="Hash password")
    role: Role = Field('staf', description="Peran pengguna")
    is_active: bool = Field(True, description="Aktif/tidak")

class StafWilayahTugas(BaseModel):
    user_id: str = Field(..., description="Ref ke users")
    nama_wilayah_tugas: str = Field(..., max_length=50)
    tipe_wilayah: TipeWilayah

class Golongan(BaseModel):
    kode_golongan: str = Field(..., description="Kode unik")
    nama_golongan: str = Field(...)
    biaya_beban: float = Field(..., ge=0)
    biaya_admin: float = Field(..., ge=0)

class TarifProgresif(BaseModel):
    id_golongan: str = Field(..., description="Ref ke golongan")
    batas_bawah_m3: int = Field(..., ge=0)
    batas_atas_m3: int = Field(..., ge=0)
    harga_per_m3: float = Field(..., ge=0)

class Pelanggan(BaseModel):
    nomor_pelanggan: str = Field(...)
    nama_pelanggan: str = Field(...)
    alamat: str = Field(...)
    desa: Optional[str] = None
    kecamatan: Optional[str] = Field(None, max_length=50)
    kabupaten: Optional[str] = Field(None, max_length=50)
    id_golongan: str = Field(...)
    nomor_meter: str = Field(...)
    status_pelanggan: StatusPelanggan = 'Aktif'

class Tagihan(BaseModel):
    nomor_nota: str = Field(...)
    id_pelanggan: str = Field(...)
    periode_tagihan: str = Field(..., description="YYYY-MM")
    tanggal_tagihan: date
    meter_awal: int = Field(..., ge=0)
    meter_akhir: int = Field(..., ge=0)
    pemakaian_m3: int = Field(..., ge=0)
    total_harga_air: float = Field(..., ge=0)
    biaya_beban: float = Field(..., ge=0)
    denda: float = Field(0, ge=0)
    total_tagihan: float = Field(..., ge=0)
    status_bayar: StatusBayar = 'Belum Bayar'
    id_petugas_catat: str = Field(...)

class DetailTagihan(BaseModel):
    id_tagihan: str = Field(...)
    keterangan_tier: str = Field(...)
    pakai_m3: int = Field(..., ge=0)
    harga_per_m3: float = Field(..., ge=0)
    subtotal: float = Field(..., ge=0)

class Pembayaran(BaseModel):
    id_tagihan: str = Field(...)
    tanggal_bayar: datetime
    jumlah_bayar: float = Field(..., ge=0)
    metode_bayar: str = Field(...)
    id_kasir: str = Field(...)
