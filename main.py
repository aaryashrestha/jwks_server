#aarya shrestha

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta, timezone
import uuid
import base64
import jwt  
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = FastAPI()


def int_to_base64url(n: int) -> str:
   #Convert integer to base64url without padding (for 'n' and 'e' fields in JWK).
    
    length = max(1, (n.bit_length() + 7) // 8)
    b = n.to_bytes(length, "big")
    s = base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
    return s

def base64url_to_int(s: str) -> int:
      #Convert base64url string back to integer.
   
    padded = s + "=" * (-len(s) % 4)
    b = base64.urlsafe_b64decode(padded)
    return int.from_bytes(b, "big")


# Key record and in-memory keystore 
class KeyRecord:
   
    def __init__(self, private_key: rsa.RSAPrivateKey, kid: str, expiry: datetime):
        self.private_key = private_key
        self.kid = kid
        self.expiry = expiry.astimezone(timezone.utc)
        self.public_key = private_key.public_key()

    def to_public_jwk(self) -> dict:
      
        nums = self.public_key.public_numbers()
        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": int_to_base64url(nums.n),
            "e": int_to_base64url(nums.e),
        }

    def private_pem_bytes(self) -> bytes:
        
       # Return private key in PEM bytes for signing (PKCS8).
        
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def public_pem_bytes(self) -> bytes:
        
        #Return public key in PEM bytes (SubjectPublicKeyInfo).
        
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

class KeyStore:
    
    def __init__(self):
        self._keys: List[KeyRecord] = []

    def generate_key(self, expires_in_seconds: int) -> KeyRecord:
      
       # Generate a new RSA key with expiry relative to now.
        
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        kid = uuid.uuid4().hex
        expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)
        record = KeyRecord(private_key=private_key, kid=kid, expiry=expiry)
        self._keys.append(record)
        return record

    def get_unexpired_jwks(self) -> List[dict]:
        
        #Return a list of public JWKs **only for non-expired keys**.
        now = datetime.now(timezone.utc)
        return [k.to_public_jwk() for k in self._keys if k.expiry > now]

    def get_signing_key(self, expired: bool = False) -> Optional[KeyRecord]:
        
          #expired=False -return an unexpired key (prefer the one with furthest expiry)
          #expired=True  -return an expired key (prefer the one whose expiry is most recent among expired)
        
        now = datetime.now(timezone.utc)
        if expired:
            candidates = [k for k in self._keys if k.expiry <= now]
            # pick the most-recent expired key (closest to now)
            candidates.sort(key=lambda x: x.expiry, reverse=True)
        else:
            candidates = [k for k in self._keys if k.expiry > now]
            # pick the key with the furthest expiry
            candidates.sort(key=lambda x: x.expiry, reverse=True)

        return candidates[0] if candidates else None

# Instantiate keystore and create sample keys:
keystore = KeyStore()
# Create one *active* key (expires in 24 hours)
keystore.generate_key(expires_in_seconds=24 * 3600)
# Create one *expired* key (expired 24 hours ago)
keystore.generate_key(expires_in_seconds=-24 * 3600)



class AuthRequest(BaseModel):
    """
    Minimal request model for /auth. Extend as needed (claims, custom fields).
    """
    sub: Optional[str] = "user@example.com"
    aud: Optional[str] = "example_audience"
 


# endpoint
@app.get("/jwks")
def jwks():
    """
    Return JWKS with only unexpired keys.
    Clients (resource servers) use this to fetch public keys and verify tokens.
    """
    return {"keys": keystore.get_unexpired_jwks()}


@app.post("/auth")
def auth(request: AuthRequest, expired: bool = Query(False, description="If true, issue a JWT signed by an *expired* key")):
    """
    Issue a JWT when POSTing JSON. If `?expired=true` is provided, the token will be:
      - signed with an expired key
      - its "exp" claim will be set to that key's expiry (in the past)
    Otherwise, issue a normally valid token signed with an unexpired key (token expiry will be <= key expiry).
    """
    key_record = keystore.get_signing_key(expired=expired)
    if key_record is None:
        # No candidate key to sign with
        raise HTTPException(status_code=404, detail="No matching signing key available (expired=%s)" % expired)

    now = datetime.now(timezone.utc)
    if expired:
        # If issuing an intentionally expired token, use the key's expiry as token expiry.
        token_exp = int(key_record.expiry.timestamp())
    else:
        # For normal token: set token expiry to now+1h but ensure it doesn't exceed the key's expiry
        candidate_exp_dt = min(now + timedelta(hours=1), key_record.expiry)
        token_exp = int(candidate_exp_dt.timestamp())

    payload = {
        "sub": request.sub,
        "aud": request.aud,
        "iat": int(now.timestamp()),
        "exp": token_exp,
        
    }

    private_pem = key_record.private_pem_bytes()
    # Include "kid" in header so clients can discover the correct JWKS entry
    headers = {"kid": key_record.kid, "alg": "RS256", "typ": "JWT"}

    token = jwt.encode(payload, private_pem, algorithm="RS256", headers=headers)

    return {
        "token": token,
        "signed_with_kid": key_record.kid,
        "key_expiry_utc": key_record.expiry.isoformat(),
        "token_exp_utc": datetime.fromtimestamp(token_exp, tz=timezone.utc).isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
