"""Google OAuth via Supabase PKCE, with opaque server-side application sessions."""
import base64
import hashlib
import os
import secrets
import time
from urllib.parse import urlencode
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, JSONResponse
from ..models.db_models import DB, LoginFlow, UserSession

router = APIRouter()
SESSION = '__Host-sms-session'
FLOW = '__Host-sms-login'


def required():
    return os.environ.get('AUTH_REQUIRED', 'false').lower() == 'true'


def fingerprint(value):
    return hashlib.sha256(value.encode()).hexdigest()


def check_origin(request):
    if request.headers.get('origin') != os.environ.get('APP_URL', '').rstrip('/'):
        raise HTTPException(403, 'Request origin is not allowed.')


def current_user(request: Request):
    if not required():
        return None  # Local single-user mode only.
    if request.method not in ('GET', 'HEAD', 'OPTIONS'):
        check_origin(request)
    token = request.cookies.get(SESSION)
    with DB() as db:
        session = db.get(UserSession, fingerprint(token)) if token else None
        if session is None or session.expires <= time.time():
            raise HTTPException(401, 'Please sign in with Google.')
        return {'id': session.user_id, 'email': session.email}


@router.get('/auth/me')
def me(request: Request):
    try:
        user = current_user(request)
    except HTTPException as exc:
        if exc.status_code != 401:
            raise
        user = None
    return {'required': required(), 'user': user}


@router.get('/auth/login')
def login():
    if not required():
        raise HTTPException(404, 'Google sign-in is not enabled.')
    token, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    with DB.begin() as db:
        db.query(LoginFlow).filter(LoginFlow.expires <= time.time()).delete()
        db.query(UserSession).filter(UserSession.expires <= time.time()).delete()
        db.add(LoginFlow(id=fingerprint(token), verifier=verifier, expires=time.time() + 600))
    query = urlencode({'provider': 'google', 'redirect_to': os.environ['APP_URL'].rstrip('/') + '/api/auth/callback',
                       'code_challenge': challenge, 'code_challenge_method': 's256'})
    response = RedirectResponse(os.environ['SUPABASE_URL'].rstrip('/') + '/auth/v1/authorize?' + query)
    response.set_cookie(FLOW, token, max_age=600, secure=True, httponly=True, samesite='lax', path='/')
    return response


@router.get('/auth/callback')
async def callback(request: Request, code: str = ''):
    failure = RedirectResponse('/?auth_error=1')
    failure.delete_cookie(FLOW, secure=True, httponly=True, samesite='lax', path='/')
    if not required():
        return failure
    token = request.cookies.get(FLOW)
    with DB.begin() as db:
        flow = db.get(LoginFlow, fingerprint(token)) if token else None
        if not flow or flow.expires <= time.time() or not code:
            return failure
        verifier = flow.verifier
        db.delete(flow)  # One attempt per browser-bound PKCE flow.
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            headers = {'apikey': os.environ['SUPABASE_ANON_KEY']}
            base = os.environ['SUPABASE_URL'].rstrip('/') + '/auth/v1'
            result = await client.post(base + '/token?grant_type=pkce', headers=headers,
                                       json={'auth_code': code, 'code_verifier': verifier})
            result.raise_for_status()
            access_token = result.json()['access_token']
            result = await client.get(base + '/user', headers={**headers, 'Authorization': 'Bearer ' + access_token})
            result.raise_for_status()
            user = result.json()
            if not user.get('id') or not user.get('email') or not user.get('email_confirmed_at'):
                return failure
            if not any(x.get('provider') == 'google' for x in user.get('identities', [])):
                return failure
    except (httpx.HTTPError, KeyError, ValueError):
        return failure
    session_token = secrets.token_urlsafe(32)
    with DB.begin() as db:
        old = request.cookies.get(SESSION)
        if old:
            db.query(UserSession).filter_by(id=fingerprint(old)).delete()
        db.add(UserSession(id=fingerprint(session_token), user_id=user['id'], email=user['email'],
                           expires=time.time() + 8 * 3600))
    response = RedirectResponse('/#workspace', status_code=303)
    response.delete_cookie(FLOW, secure=True, httponly=True, samesite='lax', path='/')
    response.set_cookie(SESSION, session_token, max_age=8 * 3600, secure=True, httponly=True, samesite='lax', path='/')
    return response


@router.post('/auth/logout')
def logout(request: Request, user=Depends(current_user)):
    token = request.cookies.get(SESSION)
    if token:
        with DB.begin() as db:
            db.query(UserSession).filter_by(id=fingerprint(token)).delete()
    response = JSONResponse({'ok': True})
    response.delete_cookie(SESSION, secure=True, httponly=True, samesite='lax', path='/')
    return response
