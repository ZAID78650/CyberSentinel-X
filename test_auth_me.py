import asyncio
from app.core.database import SessionLocal
from app.models.user import User
from app.services.auth_service import build_tokens, get_or_create_role
from app.core.security import decode_token

db = SessionLocal()
user = User(email="testoauth@example.com", full_name="Test Oauth", password_hash="", is_verified=True)
role = get_or_create_role(db, "SECURITY_ANALYST")
user.roles.append(role)
db.add(user)
db.commit()
db.refresh(user)

tokens = build_tokens(user, remember_me=True)
print("Access Token:", tokens["access_token"])

payload = decode_token(tokens["access_token"])
print("Decoded Payload:", payload)

from app.api.deps import get_current_user
from fastapi.security import HTTPAuthorizationCredentials

class MockRequest:
    headers = {}
    client = None

creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=tokens["access_token"])
try:
    current = get_current_user(request=MockRequest(), credentials=creds, db=db)
    print("User retrieved successfully:", current.email)
except Exception as e:
    print("Error in get_current_user:", e)

# cleanup
db.delete(user)
db.commit()
