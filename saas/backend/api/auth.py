import os
import json
import jwt
import requests
from fastapi import Request, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
import hashlib
from datetime import datetime
from sqlmodel import Session, select
from fastapi import Depends
from saas.backend.config import settings
from saas.backend.database import get_session
from saas.backend.models import CIApiKey

CLERK_ISSUER_URL = settings.clerk_issuer_url.rstrip("/")
# We fetch the JWKS once and cache it in memory for this prototype
_jwks_cache = None

security = HTTPBearer(auto_error=False)

def get_jwks():
    global _jwks_cache
    if not _jwks_cache:
        try:
            resp = requests.get(f"{CLERK_ISSUER_URL}/.well-known/jwks.json", timeout=5)
            resp.raise_for_status()
            _jwks_cache = resp.json()
        except Exception as e:
            raise HTTPException(status_code=500, detail="Failed to fetch JWKS")
    return _jwks_cache

def ensure_padding(s: str) -> str:
    return s + "=" * ((4 - len(s) % 4) % 4)

def get_rsa_public_key(jwk: dict) -> str:
    n_bytes = base64.urlsafe_b64decode(ensure_padding(jwk["n"]))
    e_bytes = base64.urlsafe_b64decode(ensure_padding(jwk["e"]))
    
    public_numbers = RSAPublicNumbers(
        e=int.from_bytes(e_bytes, byteorder='big'),
        n=int.from_bytes(n_bytes, byteorder='big')
    )
    public_key = public_numbers.public_key(default_backend())
    
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

def get_current_user(
    request: Request, 
    credentials: HTTPAuthorizationCredentials = Security(security),
    session: Session = Depends(get_session)
):
    api_key = request.headers.get("X-API-Key")
    if api_key:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        record = session.exec(select(CIApiKey).where(CIApiKey.key_hash == key_hash).where(CIApiKey.revoked == False)).first()
        if record:
            record.last_used_at = datetime.utcnow()
            session.add(record)
            session.commit()
            return record.tenant_id
        raise HTTPException(status_code=401, detail="Invalid or revoked API Key")

    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = credentials.credentials
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token format")
        
    kid = unverified_header.get('kid')
    if not kid:
        raise HTTPException(status_code=401, detail="Missing kid in token header")
        
    jwks = get_jwks()
    rsa_key = {}
    for key in jwks.get('keys', []):
        if key['kid'] == kid:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
            break
            
    if not rsa_key:
        raise HTTPException(status_code=401, detail="Key ID not found in JWKS")
        
    public_key = get_rsa_public_key(rsa_key)
    
    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=CLERK_ISSUER_URL
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidIssuerError:
        raise HTTPException(status_code=401, detail="Invalid issuer")
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Token validation failed: {str(e)}")
        
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Token missing subject (sub)")
        
    return user_id
