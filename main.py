from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request, UploadFile, File
import uuid
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import os, smtplib, ssl, logging, hmac, hashlib, json, base64, httpx, asyncio
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from supabase import create_client, Client
from cryptography.fernet import Fernet

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="MailFlows API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600,
)

supabase: Client = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_ANON_KEY")
)

supabase_admin: Client = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_SERVICE_KEY")
)

async def send_resend_email(to_email: str, subject: str, html: str):
    """Sends a transactional email via Resend's API. Fails silently (logs only) -
    this must never break the calling endpoint (registration, etc)."""
    resend_key = os.getenv("RESEND_API_KEY")
    if not resend_key:
        logger.info("RESEND_API_KEY not set - skipping email: " + subject)
        return False
    from_addr = os.getenv("RESEND_FROM_EMAIL", "MailFlows <onboarding@resend.dev>")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            res = await client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": "Bearer " + resend_key,
                    "Content-Type": "application/json"
                },
                json={"from": from_addr, "to": [to_email], "subject": subject, "html": html}
            )
        if res.status_code >= 400:
            logger.error("Resend send failed (" + str(res.status_code) + "): " + res.text[:300])
            return False
        return True
    except Exception as e:
        logger.error("Resend send error: " + str(e))
        return False

security = HTTPBearer()

def get_cipher():
    key = os.getenv("ENCRYPTION_KEY", "")
    if not key:
        key = base64.urlsafe_b64encode(hashlib.sha256(b"mailflow-default-key").digest()).decode()
    try:
        return Fernet(key.encode() if len(key) < 44 else key.encode())
    except Exception:
        return Fernet(base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()))

def encrypt_password(password: str) -> str:
    return get_cipher().encrypt(password.encode()).decode()

def decrypt_password(encrypted: str) -> str:
    return get_cipher().decrypt(encrypted.encode()).decode()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        user = supabase.auth.get_user(credentials.credentials)
        if not user or not user.user:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user.user
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

async def require_admin(user=Depends(get_current_user)):
    admin_email = os.getenv("ADMIN_EMAIL", "")
    if not admin_email or (user.email or "").lower() != admin_email.lower():
        raise HTTPException(status_code=403, detail="Admin access only")
    return user

# ── Admin PIN lock (second factor on top of the email check above) ──
# Every /admin/* route below depends on require_admin_locked, which layers a PIN-gated,
# time-limited session token on top of the existing admin-email check. Knowing/guessing
# the admin email (or having a leaked Supabase session) is no longer enough on its own.
ADMIN_SESSION_TTL_SECONDS = 2 * 60 * 60  # 2 hours
_admin_pin_attempts: dict = {}  # in-memory, per-process: {user_id: [failed_count, locked_until_ts]}
ADMIN_PIN_MAX_ATTEMPTS = 5
ADMIN_PIN_LOCKOUT_MINUTES = 15

def _admin_session_secret() -> str:
    # Falls back to the webhook secret if a dedicated one isn't set, so this works
    # without needing a brand-new env var right away - but setting ADMIN_SESSION_SECRET
    # separately in Railway is recommended.
    return os.getenv("ADMIN_SESSION_SECRET") or os.getenv("INBOUND_WEBHOOK_SECRET", "mailflows-admin-fallback")

def _make_admin_session_token(user_id: str) -> str:
    expires_at = int((datetime.utcnow() + timedelta(seconds=ADMIN_SESSION_TTL_SECONDS)).timestamp())
    payload = f"{user_id}:{expires_at}"
    sig = hmac.new(_admin_session_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()

def _verify_admin_session_token(token: str, user_id: str) -> bool:
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        parts = decoded.split(":")
        if len(parts) != 3:
            return False
        token_user_id, expires_at, sig = parts
        if token_user_id != user_id:
            return False
        payload = f"{token_user_id}:{expires_at}"
        expected_sig = hmac.new(_admin_session_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return False
        if int(expires_at) < int(datetime.utcnow().timestamp()):
            return False
        return True
    except Exception:
        return False

async def require_admin_locked(request: Request, user=Depends(require_admin)):
    token = request.headers.get("X-Admin-Session", "")
    if not token or not _verify_admin_session_token(token, user.id):
        raise HTTPException(status_code=401, detail="Admin dashboard is locked - enter the admin PIN")
    return user

class AdminPinModel(BaseModel):
    pin: str

@app.get("/admin/check")
async def admin_check(user=Depends(require_admin)):
    # Email-only check, no PIN required - just for the frontend to decide whether to
    # show the Admin nav item at all. Does NOT grant access to any real admin data.
    return {"is_admin": True}

@app.get("/admin/alerts-summary")
async def admin_alerts_summary(since: Optional[str] = None, user=Depends(require_admin)):
    # Email-only (no PIN) - this is just a glance-able badge count, same sensitivity
    # level as /admin/check. Real ticket/payment/user content still requires unlocking.
    #
    # `since` is an ISO timestamp the frontend sends (its last-seen time, stored in
    # localStorage). Only items created AFTER it count - this is what makes the badge
    # show real NEW activity instead of a permanently-nonzero count of everything open.
    if not since:
        since = (datetime.utcnow() - timedelta(days=1)).isoformat()

    def _safe_count(table: str, filters: list) -> int:
        try:
            q = supabase_admin.table(table).select("id", count="exact")
            for col, op, val in filters:
                q = getattr(q, op)(col, val)
            return q.execute().count or 0
        except Exception as e:
            logger.error(f"admin_alerts_summary {table} query failed: " + str(e))
            return 0

    new_users = _safe_count("users", [("created_at", "gte", since)])
    new_payments = _safe_count("payments", [("status", "eq", "success"), ("created_at", "gte", since)])
    new_tickets = _safe_count("support_tickets", [("created_at", "gte", since)])
    # Tickets a user replied to again (status flips back to 'open') also count as "new"
    # activity needing attention, not just brand-new tickets.
    reopened_tickets = _safe_count("support_tickets", [("status", "eq", "open"), ("updated_at", "gte", since)])

    # Persistent signal, NOT timestamp-based: is anyone currently close to running out
    # of scraper or verification credits right now? This should show as long as it's
    # true, not just once - it's "pay attention to demand," not "something new happened."
    running_low = 0
    try:
        near_limit_users = supabase_admin.table("users").select(
            "id, plan, scraper_used_this_month, scraper_limit, verification_used_this_month, verification_limit"
        ).neq("plan", "free").execute()
        for u in (near_limit_users.data or []):
            s_used, s_limit = u.get("scraper_used_this_month") or 0, u.get("scraper_limit") or 0
            v_used, v_limit = u.get("verification_used_this_month") or 0, u.get("verification_limit") or 0
            if (s_limit and s_used >= s_limit * 0.9) or (v_limit and v_used >= v_limit * 0.9):
                running_low += 1
    except Exception as e:
        logger.error("admin_alerts_summary low-limit query failed: " + str(e))

    total = new_users + new_payments + new_tickets + reopened_tickets + (1 if running_low else 0)
    return {
        "new_users": new_users,
        "new_payments": new_payments,
        "new_tickets": new_tickets,
        "reopened_tickets": reopened_tickets,
        "users_running_low": running_low,
        "total": total
    }

@app.post("/admin/verify-pin")
async def verify_admin_pin(data: AdminPinModel, user=Depends(require_admin)):
    admin_pin = os.getenv("ADMIN_PIN", "")
    admin_email = os.getenv("ADMIN_EMAIL", "")
    attempts = _admin_pin_attempts.get(user.id, [0, 0])
    now_ts = datetime.utcnow().timestamp()

    if attempts[1] and now_ts < attempts[1]:
        wait_min = round((attempts[1] - now_ts) / 60, 1)
        raise HTTPException(status_code=429, detail=f"Too many wrong PIN attempts. Try again in {wait_min} minute(s).")

    if not admin_pin:
        logger.error("ADMIN_PIN not set - admin dashboard lock cannot be enforced!")
        raise HTTPException(status_code=500, detail="Admin PIN not configured on the server")

    if not hmac.compare_digest(data.pin, admin_pin):
        attempts[0] += 1
        if attempts[0] >= ADMIN_PIN_MAX_ATTEMPTS:
            attempts[1] = now_ts + (ADMIN_PIN_LOCKOUT_MINUTES * 60)
            attempts[0] = 0
        _admin_pin_attempts[user.id] = attempts
        if admin_email:
            await send_resend_email(
                admin_email,
                "⚠️ MailFlows admin PIN entered incorrectly",
                f"<p>A wrong admin PIN was entered for the MailFlows admin dashboard.</p><p>Attempt {attempts[0]} of {ADMIN_PIN_MAX_ATTEMPTS} before a {ADMIN_PIN_LOCKOUT_MINUTES}-minute lockout.</p><p>Time (UTC): {datetime.utcnow().isoformat()}</p>"
            )
        raise HTTPException(status_code=403, detail="Incorrect PIN")

    _admin_pin_attempts.pop(user.id, None)
    token = _make_admin_session_token(user.id)
    if admin_email:
        await send_resend_email(
            admin_email,
            "🔓 MailFlows admin dashboard unlocked",
            f"<p>The MailFlows admin dashboard was just unlocked.</p><p>Time (UTC): {datetime.utcnow().isoformat()}</p><p>If this wasn't you, rotate ADMIN_PIN in Railway immediately.</p>"
        )
    return {"admin_session_token": token, "expires_in": ADMIN_SESSION_TTL_SECONDS}

class RegisterModel(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class LoginModel(BaseModel):
    email: EmailStr
    password: str

class SMTPModel(BaseModel):
    label: str
    host: str
    port: int = 587
    email: str
    password: str
    daily_limit: int = 500

class CampaignModel(BaseModel):
    name: str
    subject: str
    template_body: str
    from_name: Optional[str] = None
    reply_to: Optional[str] = None
    contact_ids: Optional[List[str]] = []
    niche: Optional[str] = None
    status: Optional[str] = "draft"

class SendTestModel(BaseModel):
    smtp_id: str
    to_email: str
    subject: str = "Test Email from MailFlows"

class ScrapeModel(BaseModel):
    niche: str
    limit: int = 25

class InitiatePaymentModel(BaseModel):
    plan: str
    currency: str = "NGN"

CREDIT_PACKS = {
    # Real cost basis (Tavily, per email found): ~$0.012/credit, confirmed linear
    # across 10/100/150 volumes. Flat $0.05 margin added per pack (not per credit).
    "small": {"credits": 10, "amount_ngn": 27200, "amount_usd": 17},     # ₦272 / $0.17 - 10 email credits
    "medium": {"credits": 50, "amount_ngn": 104000, "amount_usd": 65},  # ₦1,040 / $0.65 - 50 email credits
    "large": {"credits": 150, "amount_ngn": 296000, "amount_usd": 185}  # ₦2,960 / $1.85 - 150 email credits
}

# Verification credit top-ups - separate pool from scraper credits.
# Real cost basis (Reoon, per verification): ~$0.0013/credit, confirmed linear
# across 10/100/150 volumes - roughly 9x cheaper per unit than scraping.
# Same flat $0.05 margin per pack as scraper credits.
VERIFICATION_CREDIT_PACKS = {
    "small": {"credits": 10, "amount_ngn": 10000, "amount_usd": 6},     # ₦100 / $0.06 - 10 verification credits
    "medium": {"credits": 50, "amount_ngn": 18500, "amount_usd": 12},   # ₦185 / $0.12 - 50 verification credits
    "large": {"credits": 150, "amount_ngn": 39000, "amount_usd": 25}    # ₦390 / $0.25 - 150 verification credits
}

PLANS = {
    "personal": {
        "name": "Personal",
        "amount_ngn": 650000,
        "amount_usd": 400,
        "daily_limit": 1200,
        "contacts_limit": 20000,
        "smtp_limit": 3,
        "scraper_limit": 100,
        "campaigns_limit": 25,
        "ai_personalization": True
    },
    "corporate": {
        "name": "Corporate",
        "amount_ngn": 2400000,
        "amount_usd": 1500,
        "daily_limit": 4500,
        "contacts_limit": 70000,
        "smtp_limit": 10,
        "scraper_limit": 500,
        "campaigns_limit": 50,
        "ai_personalization": True
    }
}

FREE_PLAN = {
    "daily_limit": 100,
    "contacts_limit": 500,
    "smtp_limit": 1,
    "scraper_limit": 4,
    "campaigns_limit": 5,
}

@app.post("/payments/downgrade")
async def downgrade_to_free(user=Depends(get_current_user)):
    """Self-serve downgrade - no support ticket needed. Takes effect immediately
    (MVP behavior - if you later want it to wait until the paid period ends,
    check plan_expires_at here instead of downgrading right away)."""
    supabase_admin.table("users").update({
        "plan": "free",
        "daily_limit": FREE_PLAN["daily_limit"],
        "contacts_limit": FREE_PLAN["contacts_limit"],
        "smtp_limit": FREE_PLAN["smtp_limit"],
        "scraper_limit": FREE_PLAN["scraper_limit"],
        "campaigns_limit": FREE_PLAN["campaigns_limit"],
        "plan_expires_at": None,
    }).eq("id", user.id).execute()
    return {"message": "You've been moved to the Free plan.", "plan": "free"}

@app.get("/")
def root():
    return {"message": "MailFlows API v2.0 running", "status": "ok"}

@app.get("/ping")
def ping():
    return {"pong": True, "time": datetime.utcnow().isoformat()}

@app.options("/{path:path}")
async def options_handler(path: str):
    return {"ok": True}

@app.post("/auth/register")
async def register(data: RegisterModel):
    try:
        res = supabase.auth.sign_up({
            "email": data.email,
            "password": data.password,
            "options": {"data": {"full_name": data.full_name}}
        })
        if res.user:
            try:
                supabase_admin.table("users").insert({
                    "id": res.user.id,
                    "email": data.email,
                    "full_name": data.full_name,
                    "plan": "free",
                    "daily_limit": 100,
                    "emails_sent_today": 0
                }).execute()
            except Exception:
                pass
            try:
                welcome_html = (
                    "<div style='font-family:sans-serif;max-width:480px;margin:0 auto'>"
                    "<h2 style='color:#00d4aa'>Welcome to MailFlows, " + (data.full_name or "there") + "!</h2>"
                    "<p>Your account is ready. First, confirm your email using the link we just sent "
                    "from Supabase, then log in and connect your Gmail account to start sending campaigns.</p>"
                    "<p style='color:#8b949e;font-size:13px'>If you didn't sign up for MailFlows, you can ignore this email.</p>"
                    "</div>"
                )
                await send_resend_email(data.email, "Welcome to MailFlows", welcome_html)
            except Exception as e:
                logger.error("Welcome email failed: " + str(e))
            return {"message": "Account created. Check your email to verify.", "user_id": res.user.id}
        raise HTTPException(status_code=400, detail="Registration failed")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

class RefreshModel(BaseModel):
    refresh_token: str

@app.post("/auth/refresh")
async def refresh_session(data: RefreshModel):
    try:
        res = supabase.auth.refresh_session(data.refresh_token)
        if res.session:
            return {
                "access_token": res.session.access_token,
                "refresh_token": res.session.refresh_token
            }
        raise HTTPException(status_code=401, detail="Session expired, please log in again")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Session expired, please log in again")

class ResendConfirmModel(BaseModel):
    email: str

@app.post("/auth/resend-confirmation")
async def resend_confirmation(data: ResendConfirmModel):
    try:
        supabase.auth.resend({"type": "signup", "email": data.email})
        return {"message": "Confirmation email resent. Please check your inbox (and spam folder)."}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Could not resend confirmation email: " + str(e))

@app.post("/auth/login")
async def login(data: LoginModel):
    try:
        res = supabase.auth.sign_in_with_password({"email": data.email, "password": data.password})
        if res.user:
            try:
                profile = supabase_admin.table("users").select("*").eq("id", res.user.id).single().execute()
                profile_data = profile.data or {}
            except Exception:
                profile_data = {}
            return {
                "access_token": res.session.access_token,
                "refresh_token": res.session.refresh_token,
                "user": {
                    "id": res.user.id,
                    "email": res.user.email,
                    "full_name": profile_data.get("full_name", res.user.email.split("@")[0]),
                    "plan": profile_data.get("plan", "free"),
                    "daily_limit": profile_data.get("daily_limit", 100),
                    "emails_sent_today": profile_data.get("emails_sent_today", 0)
                }
            }
        raise HTTPException(status_code=401, detail="Invalid credentials")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid email or password")

@app.get("/auth/me")
async def get_me(user=Depends(get_current_user)):
    try:
        profile = supabase_admin.table("users").select("*").eq("id", user.id).single().execute()
        return profile.data
    except Exception:
        return {"id": user.id, "email": user.email, "plan": "free"}

async def maybe_cleanup_old_records(user_id: str):
    """Deletes sent emails and replies older than 90 days, for privacy/security.
    Throttled to check once per day per user, not on every dashboard poll."""
    today = datetime.utcnow().strftime("%Y-%m-%d")
    try:
        profile = supabase_admin.table("users").select("last_cleanup_date").eq("id", user_id).single().execute()
        if profile.data and profile.data.get("last_cleanup_date") == today:
            return
    except Exception:
        pass

    cutoff = (datetime.utcnow() - timedelta(days=90)).isoformat()
    try:
        supabase_admin.table("emails_sent").delete().eq("user_id", user_id).lt("sent_at", cutoff).execute()
        supabase_admin.table("replies").delete().eq("user_id", user_id).lt("received_at", cutoff).execute()
        supabase_admin.table("users").update({"last_cleanup_date": today}).eq("id", user_id).execute()
    except Exception as e:
        logger.error("maybe_cleanup_old_records failed for user " + user_id + ": " + str(e))

@app.get("/dashboard/stats")
async def get_stats(user=Depends(get_current_user)):
    uid = user.id
    await maybe_cleanup_old_records(uid)
    try:
        campaigns = supabase_admin.table("campaigns").select("id", count="exact").eq("user_id", uid).execute()
        contacts = supabase_admin.table("scraped_contacts").select("id", count="exact").eq("user_id", uid).execute()
        sent = supabase_admin.table("emails_sent").select("id", count="exact").eq("user_id", uid).execute()
        replies = supabase_admin.table("replies").select("id", count="exact").eq("user_id", uid).execute()
        unread = supabase_admin.table("replies").select("id", count="exact").eq("user_id", uid).eq("is_read", False).execute()

        quota = await get_scraper_quota(uid)
        verify_quota = await get_verification_quota(uid)

        profile = supabase_admin.table("users").select(
            "plan, contacts_limit, campaigns_limit"
        ).eq("id", uid).single().execute()
        pdata = profile.data or {}
        plan = (pdata.get("plan") or "free").lower()
        plan_fallback = {"free": {"contacts_limit": 500, "campaigns_limit": 5},
                          "personal": {"contacts_limit": 20000, "campaigns_limit": 25},
                          "corporate": {"contacts_limit": 70000, "campaigns_limit": 50}}
        contacts_limit = pdata.get("contacts_limit") or plan_fallback.get(plan, plan_fallback["free"])["contacts_limit"]
        campaigns_limit = pdata.get("campaigns_limit") or plan_fallback.get(plan, plan_fallback["free"])["campaigns_limit"]

        return {
            "campaigns": campaigns.count or 0,
            "contacts": contacts.count or 0,
            "emails_sent": sent.count or 0,
            "replies": replies.count or 0,
            "unread_replies": unread.count or 0,
            "scraper_used": quota["used"],
            "scraper_limit": quota["limit"],
            "scraper_bonus_credits": quota["bonus_credits"],
            "verification_used": verify_quota["used"],
            "verification_limit": verify_quota["limit"],
            "verification_bonus_credits": verify_quota["bonus_credits"],
            "contacts_limit": contacts_limit,
            "campaigns_limit": campaigns_limit
        }
    except Exception:
        return {"campaigns": 0, "contacts": 0, "emails_sent": 0, "replies": 0, "unread_replies": 0, "scraper_used": 0, "scraper_limit": 4}

@app.post("/smtp/add")
async def add_smtp(data: SMTPModel, user=Depends(get_current_user)):
    encrypted_pw = encrypt_password(data.password)
    result = supabase_admin.table("smtp_accounts").insert({
        "user_id": user.id,
        "label": data.label,
        "host": data.host,
        "port": data.port,
        "email": data.email,
        "password_encrypted": encrypted_pw,
        "daily_limit": data.daily_limit,
        "sent_today": 0,
        "is_active": True
    }).execute()
    return {"message": "SMTP account added", "id": result.data[0]["id"]}

@app.get("/smtp/list")
async def list_smtp(user=Depends(get_current_user)):
    result = supabase_admin.table("smtp_accounts").select(
        "id, label, host, port, email, daily_limit, sent_today, is_active, last_tested"
    ).eq("user_id", user.id).execute()
    return result.data

@app.post("/smtp/test")
async def test_smtp(data: SendTestModel, user=Depends(get_current_user)):
    smtp_rec = supabase_admin.table("smtp_accounts").select("*").eq("id", data.smtp_id).eq("user_id", user.id).single().execute()
    if not smtp_rec.data:
        raise HTTPException(status_code=404, detail="SMTP account not found")
    rec = smtp_rec.data
    try:
        password = decrypt_password(rec["password_encrypted"])
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decrypt password. Please re-add this SMTP account.")
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = data.subject
        msg["From"] = rec["email"]
        msg["To"] = data.to_email
        html = "<h2 style='color:#00d4aa'>MailFlows Test Email</h2><p>Your SMTP is configured correctly!</p>"
        msg.attach(MIMEText(html, "html"))
        context = ssl.create_default_context()
        with smtplib.SMTP(rec["host"], rec["port"], timeout=15) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(rec["email"], password)
            server.sendmail(rec["email"], data.to_email, msg.as_string())
        supabase_admin.table("smtp_accounts").update(
            {"last_tested": datetime.utcnow().isoformat()}
        ).eq("id", data.smtp_id).execute()
        return {"message": "Test email sent successfully!", "status": "ok"}
    except smtplib.SMTPAuthenticationError:
        raise HTTPException(status_code=400, detail="Authentication failed. Use Gmail App Password not your regular password. Go to myaccount.google.com > Security > App Passwords")
    except smtplib.SMTPConnectError:
        raise HTTPException(status_code=400, detail="Could not connect to SMTP server. Check host and port.")
    except Exception as e:
        raise HTTPException(status_code=400, detail="SMTP error: " + str(e))

@app.delete("/smtp/{smtp_id}")
async def delete_smtp(smtp_id: str, user=Depends(get_current_user)):
    supabase_admin.table("smtp_accounts").delete().eq("id", smtp_id).eq("user_id", user.id).execute()
    return {"message": "SMTP account deleted"}

@app.get("/contacts")
async def get_contacts(user=Depends(get_current_user)):
    result = supabase_admin.table("scraped_contacts").select("*").eq("user_id", user.id).order("created_at", desc=True).execute()
    return result.data

@app.post("/contacts/add")
async def add_contact(contact: dict, user=Depends(get_current_user)):
    contact["user_id"] = user.id
    result = supabase_admin.table("scraped_contacts").insert(contact).execute()
    return result.data[0]

class BulkAddModel(BaseModel):
    raw_text: str
    niche: Optional[str] = None

@app.post("/contacts/bulk-add")
async def bulk_add_contacts(data: BulkAddModel, user=Depends(get_current_user)):
    email_re = _re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    lines = [l.strip() for l in data.raw_text.splitlines() if l.strip()]

    parsed = []
    skipped = 0
    for line in lines:
        # Supports: "email" | "name,email" | "name,email,company"
        parts = [p.strip() for p in line.split(",")]
        if len(parts) == 1:
            name, email, company = "", parts[0], ""
        elif len(parts) == 2:
            name, email, company = parts[0], parts[1], ""
        else:
            name, email, company = parts[0], parts[1], parts[2]

        if not email_re.match(email):
            skipped += 1
            continue

        parsed.append({
            "user_id": user.id,
            "name": name,
            "email": email,
            "company": company,
            "niche": data.niche or "",
            "source": "manual",
            "is_verified": False
        })

    added = 0
    for c in parsed:
        try:
            supabase_admin.table("scraped_contacts").insert(c).execute()
            added += 1
        except Exception:
            skipped += 1

    return {"added": added, "skipped": skipped, "total_lines": len(lines)}

@app.delete("/contacts/{contact_id}")
async def delete_contact(contact_id: str, user=Depends(get_current_user)):
    supabase_admin.table("scraped_contacts").delete().eq("id", contact_id).eq("user_id", user.id).execute()
    return {"message": "Contact deleted"}

import re as _re

_vendor_health = {"reoon_fail_streak": 0, "reoon_alerted": False,
                   "tavily_fail_streak": 0, "tavily_alerted": False}

async def _note_vendor_result(vendor: str, ok: bool):
    """Tracks consecutive failures per external vendor (Reoon, Tavily). After a
    few in a row, emails ADMIN_EMAIL once (not on every single failure) - this is
    usually caused by the vendor account running out of paid credits, which
    otherwise fails silently and just quietly degrades to a worse fallback."""
    streak_key = vendor + "_fail_streak"
    alerted_key = vendor + "_alerted"
    if ok:
        _vendor_health[streak_key] = 0
        _vendor_health[alerted_key] = False
        return
    _vendor_health[streak_key] += 1
    if _vendor_health[streak_key] >= 5 and not _vendor_health[alerted_key]:
        _vendor_health[alerted_key] = True
        admin_email = os.getenv("ADMIN_EMAIL")
        if admin_email:
            try:
                await send_resend_email(
                    admin_email,
                    f"⚠️ {vendor.title()} has failed {_vendor_health[streak_key]} times in a row",
                    f"<p>{vendor.title()} API calls have failed {_vendor_health[streak_key]} times in a row on MailFlow.</p>"
                    f"<p>This usually means the {vendor.title()} account is out of credits, the API key is wrong, "
                    f"or the vendor is down. MailFlow is still working - it's silently falling back to a lower-quality "
                    f"method - but check your {vendor.title()} dashboard when you can.</p>"
                )
            except Exception as e:
                logger.error(f"Could not send {vendor} health alert email: " + str(e))

async def verify_single_email(email: str) -> dict:
    """Check if an email is real/deliverable. Tries Reoon first (cheaper, high accuracy),
    then Hunter.io if configured, falls back to a free syntax + mail-server (MX) check otherwise."""
    reoon_key = os.getenv("REOON_API_KEY")
    if reoon_key:
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                res = await client.get(
                    "https://emailverifier.reoon.com/api/v1/verify",
                    params={"email": email, "key": reoon_key, "mode": "power"}
                )
            if res.status_code == 200:
                result = res.json()
                status = result.get("status", "unknown")
                if status == "error":
                    logger.error("Reoon returned an ERROR (not unknown) for " + email + ": " + str(result.get("reason", result)))
                    # this is a real API problem (bad key/no credits/bad request), not a genuine
                    # "we don't know" result - fall through to Hunter/basic instead of lying
                    await _note_vendor_result("reoon", ok=False)
                else:
                    await _note_vendor_result("reoon", ok=True)
                    mapping = {
                        "safe": "valid",
                        "invalid": "invalid",
                        "disabled": "invalid",
                        "disposable": "invalid",
                        "spamtrap": "invalid",
                        "inbox_full": "risky",
                        "catch_all": "risky",
                        "role_account": "risky",
                        "unknown": "unknown"
                    }
                    return {"status": mapping.get(status, "unknown"), "method": "reoon"}
            else:
                logger.error("Reoon HTTP " + str(res.status_code) + " for " + email + ": " + res.text[:300])
                await _note_vendor_result("reoon", ok=False)
        except Exception as e:
            logger.error("Reoon verify error for " + email + ": " + str(e))
            await _note_vendor_result("reoon", ok=False)
            # fall through to Hunter/basic check below

    hunter_key = os.getenv("HUNTER_API_KEY")
    if hunter_key:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                res = await client.get(
                    "https://api.hunter.io/v2/email-verifier",
                    params={"email": email, "api_key": hunter_key}
                )
            if res.status_code == 200:
                result = res.json().get("data", {}).get("result", "unknown")
                mapping = {"deliverable": "valid", "undeliverable": "invalid", "risky": "risky"}
                return {"status": mapping.get(result, "unknown"), "method": "hunter"}
        except Exception as e:
            logger.error("Hunter verify error for " + email + ": " + str(e))
            # fall through to basic check below

    # Free fallback: syntax check + does the domain actually have a mail server?
    if not _re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        return {"status": "invalid", "method": "basic"}
    domain = email.split("@")[-1]
    try:
        import dns.resolver
    except ImportError:
        return {"status": "unknown", "method": "basic"}
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        if len(answers) > 0:
            return {"status": "valid", "method": "basic"}
    except Exception:
        pass
    return {"status": "invalid", "method": "basic"}

class VerifyContactsModel(BaseModel):
    contact_ids: Optional[List[str]] = None  # None = verify all unverified contacts

@app.post("/contacts/verify")
async def verify_contacts(data: VerifyContactsModel, user=Depends(get_current_user)):
    quota = await get_verification_quota(user.id)
    if quota["remaining"] <= 0:
        raise HTTPException(
            status_code=403,
            detail=f"Verification limit reached ({quota['used']}/{quota['limit']} this month, "
                   f"+{quota['bonus_credits']} bonus). Buy more verification credits or upgrade your plan."
        )

    query = supabase_admin.table("scraped_contacts").select("id,email").eq("user_id", user.id)
    if data.contact_ids:
        query = query.in_("id", data.contact_ids)
    else:
        query = query.eq("verification_status", "unverified")
    contacts = query.limit(min(50, quota["remaining"])).execute()

    if not contacts.data:
        return {"verified": 0, "results": {}, "message": "No unverified contacts found"}

    results = {"valid": 0, "invalid": 0, "risky": 0, "unknown": 0}
    verified_count = 0
    for c in contacts.data:
        v = await verify_single_email(c["email"])
        status = v["status"]
        results[status] = results.get(status, 0) + 1
        supabase_admin.table("scraped_contacts").update({
            "verification_status": status,
            "is_verified": status == "valid",
            "verified_at": datetime.utcnow().isoformat()
        }).eq("id", c["id"]).execute()
        verified_count += 1
        await asyncio.sleep(0.3)  # gentle pacing to avoid rate limits

    # Charge monthly allowance first, then bonus (purchased) verification credits
    monthly_remaining = max(quota["limit"] - quota["used"], 0)
    from_monthly = min(verified_count, monthly_remaining)
    from_bonus = verified_count - from_monthly
    new_used = quota["used"] + from_monthly
    new_bonus = max(quota["bonus_credits"] - from_bonus, 0)
    supabase_admin.table("users").update({
        "verification_used_this_month": new_used,
        "verification_bonus_credits": new_bonus
    }).eq("id", user.id).execute()

    return {
        "verified": verified_count,
        "results": results,
        "verification_used": new_used,
        "verification_limit": quota["limit"],
        "bonus_credits_remaining": new_bonus
    }

async def get_scraper_quota(user_id: str) -> dict:
    """Returns current scraper usage/limit, resetting the monthly counter if a new month started.
    Bonus credits (from one-time top-up purchases) don't reset monthly and are used after
    the plan's monthly allowance runs out."""
    try:
        profile = supabase_admin.table("users").select(
            "plan, scraper_limit, scraper_used_this_month, scraper_reset_month, scraper_bonus_credits"
        ).eq("id", user_id).single().execute()
        profile_data = profile.data
    except Exception as e:
        logger.error("get_scraper_quota query failed for user " + user_id + ": " + str(e))
        profile_data = None

    plan_fallback_limits = {"free": 4, "personal": 100, "corporate": 500}
    limit = 4
    used = 0
    bonus = 0
    if profile_data:
        plan = (profile_data.get("plan") or "free").lower()
        limit = profile_data.get("scraper_limit") or plan_fallback_limits.get(plan, 4)
        used = profile_data.get("scraper_used_this_month") or 0
        bonus = profile_data.get("scraper_bonus_credits") or 0
        current_month = datetime.utcnow().strftime("%Y-%m")
        if profile_data.get("scraper_reset_month") != current_month:
            used = 0
            try:
                supabase_admin.table("users").update({
                    "scraper_used_this_month": 0,
                    "scraper_reset_month": current_month
                }).eq("id", user_id).execute()
            except Exception as e:
                logger.error("get_scraper_quota reset update failed: " + str(e))

    monthly_remaining = max(limit - used, 0)
    return {
        "limit": limit,
        "used": used,
        "bonus_credits": bonus,
        "remaining": monthly_remaining + bonus
    }

async def get_verification_quota(user_id: str) -> dict:
    """Email verification has its own monthly USAGE counter and its own bonus-credit
    pool, but its LIMIT always mirrors the scraper limit exactly - it calls
    get_scraper_quota() directly for that number instead of re-deriving it, so the two
    can never drift out of sync (which is what was happening: a corporate-plan user
    was seeing scraper=500 but verification=4, because this function used to look up
    "scraper_limit" itself via a second, separate query+fallback that could resolve
    differently than the scraper endpoint's own resolution)."""
    scraper = await get_scraper_quota(user_id)
    limit = scraper["limit"]

    try:
        profile = supabase_admin.table("users").select(
            "verification_used_this_month, verification_reset_month, verification_bonus_credits"
        ).eq("id", user_id).single().execute()
        profile_data = profile.data
    except Exception as e:
        logger.error("get_verification_quota query failed for user " + user_id + ": " + str(e))
        profile_data = None

    used = 0
    bonus = 0
    if profile_data:
        used = profile_data.get("verification_used_this_month") or 0
        bonus = profile_data.get("verification_bonus_credits") or 0
        current_month = datetime.utcnow().strftime("%Y-%m")
        if profile_data.get("verification_reset_month") != current_month:
            used = 0
            try:
                supabase_admin.table("users").update({
                    "verification_used_this_month": 0,
                    "verification_reset_month": current_month
                }).eq("id", user_id).execute()
            except Exception as e:
                logger.error("get_verification_quota reset update failed: " + str(e))

    monthly_remaining = max(limit - used, 0)
    return {
        "limit": limit,
        "used": used,
        "bonus_credits": bonus,
        "remaining": monthly_remaining + bonus
    }

# ── Company website scraper: finds emails businesses have published on their own site ──
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

EMAIL_PATTERN = _re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
JUNK_EMAIL_MARKERS = ["example.com", "yourdomain", "sentry.io", "wixpress", "godaddy",
                      ".png", ".jpg", ".jpeg", ".gif", ".svg", "@2x", "schema.org"]

def is_allowed_by_robots(url: str) -> bool:
    """Never scrape a page whose robots.txt explicitly disallows it."""
    try:
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        rp = RobotFileParser()
        rp.set_url(robots_url)
        rp.read()
        return rp.can_fetch("MailFlowsBot", url)
    except Exception:
        return True  # if robots.txt is unreadable, default to allowed rather than blocking everything

async def extract_emails_from_page(client, url: str) -> set:
    if not is_allowed_by_robots(url):
        return set()
    try:
        res = await client.get(
            url, timeout=8,
            headers={"User-Agent": "Mozilla/5.0 (compatible; MailFlowsBot/1.0; +https://mailflows.org/bot)"}
        )
        if res.status_code != 200:
            return set()
        found = set(EMAIL_PATTERN.findall(res.text))
        return {e for e in found if not any(marker in e.lower() for marker in JUNK_EMAIL_MARKERS)}
    except Exception:
        return set()

async def scrape_company_websites(niche: str, limit: int) -> list:
    """Finds business websites for a niche via Tavily's search API,
    then checks their own published contact pages for emails they've chosen to share."""
    tavily_key = os.getenv("TAVILY_API_KEY")
    if not tavily_key:
        return []

    results = []
    async with httpx.AsyncClient() as client:
        try:
            search_res = await client.post(
                "https://api.tavily.com/search",
                headers={"Authorization": "Bearer " + tavily_key, "Content-Type": "application/json"},
                json={"query": niche + " contact", "max_results": min(limit, 10), "search_depth": "basic"}
            )
            if search_res.status_code != 200:
                logger.error("Tavily HTTP " + str(search_res.status_code) + ": " + search_res.text[:300])
                await _note_vendor_result("tavily", ok=False)
                return []
            items = search_res.json().get("results", [])
            await _note_vendor_result("tavily", ok=True)
        except Exception as e:
            logger.error("Tavily search failed: " + str(e))
            await _note_vendor_result("tavily", ok=False)
            return []

        for item in items:
            site_url = item.get("url")
            if not site_url:
                continue
            parsed = urlparse(site_url)
            domain = parsed.netloc
            company_name = (item.get("title") or "").split("|")[0].split("-")[0].strip()

            candidate_urls = [site_url] + [
                f"{parsed.scheme}://{domain}{path}" for path in ["/contact", "/contact-us", "/about"]
            ]

            found_emails = set()
            for u in candidate_urls[:3]:
                found_emails |= await extract_emails_from_page(client, u)
                if found_emails:
                    break
                await asyncio.sleep(1)  # be polite - don't hammer the same domain

            for email in found_emails:
                results.append({
                    "name": "",
                    "email": email,
                    "company": company_name,
                    "website": site_url,
                    "source": "web_scrape"
                })
            if len(results) >= limit:
                break

    return results

@app.post("/scraper/search")
async def scrape_emails(data: ScrapeModel, user=Depends(get_current_user)):
    quota = await get_scraper_quota(user.id)
    if quota["remaining"] <= 0:
        raise HTTPException(
            status_code=403,
            detail=f"Scraper limit reached ({quota['used']}/{quota['limit']} this month). Upgrade your plan to scrape more contacts."
        )

    # Tavily itself bills per search query, but we charge users per email actually
    # found and delivered (not per search) - see the charging logic below.
    try:
        results = await scrape_company_websites(data.niche, data.limit)
    except Exception as e:
        logger.error("Website scraper error: " + str(e))
        results = []

    seen = set()
    unique = []
    for r in results:
        if r["email"] not in seen:
            seen.add(r["email"])
            unique.append(r)

    # One credit = one email address actually found and returned, not one search.
    # A search that finds nothing costs nothing. Cap results to what the user can
    # afford (monthly allowance first, then bonus top-up credits).
    monthly_remaining = max(quota["limit"] - quota["used"], 0)
    affordable = monthly_remaining + quota["bonus_credits"]
    if len(unique) > affordable:
        unique = unique[:affordable]

    charge = len(unique)
    from_monthly = min(charge, monthly_remaining)
    from_bonus = charge - from_monthly
    new_used = quota["used"] + from_monthly
    new_bonus = max(quota["bonus_credits"] - from_bonus, 0)
    supabase_admin.table("users").update({
        "scraper_used_this_month": new_used,
        "scraper_bonus_credits": new_bonus
    }).eq("id", user.id).execute()

    return {
        "results": unique,
        "count": len(unique),
        "niche": data.niche,
        "scraper_used": new_used,
        "scraper_limit": quota["limit"],
        "bonus_credits_remaining": new_bonus
    }

@app.post("/scraper/save")
async def save_scraped(contacts: List[dict], user=Depends(get_current_user)):
    # Quota was already enforced and counted at search time (that's when real
    # credits are spent). Saving just copies already-fetched results into your
    # permanent contacts list, so it doesn't spend anything further.
    saved = 0
    for c in contacts:
        try:
            supabase_admin.table("scraped_contacts").insert({
                "user_id": user.id,
                "name": c.get("name", ""),
                "email": c.get("email", ""),
                "company": c.get("company", ""),
                "website": c.get("website", ""),
                "niche": c.get("niche", ""),
                "source": c.get("source", "scraper"),
                "is_verified": False
            }).execute()
            saved += 1
        except Exception:
            pass
    return {"message": str(saved) + " contacts saved", "saved": saved}

@app.post("/campaigns/create")
async def create_campaign(data: CampaignModel, user=Depends(get_current_user)):
    result = supabase_admin.table("campaigns").insert({
        "user_id": user.id,
        "name": data.name,
        "subject": data.subject,
        "template_body": data.template_body,
        "from_name": data.from_name,
        "reply_to": data.reply_to,
        "niche": data.niche,
        "status": data.status or "draft",
        "total_contacts": len(data.contact_ids),
        "sent_count": 0,
        "open_count": 0,
        "reply_count": 0,
        "is_ai_personalized": True
    }).execute()
    return result.data[0]

class CampaignStatusUpdate(BaseModel):
    status: str
    sent_count: Optional[int] = None

@app.patch("/campaigns/{campaign_id}/status")
async def update_campaign_status(campaign_id: str, data: CampaignStatusUpdate, user=Depends(get_current_user)):
    update = {"status": data.status}
    if data.sent_count is not None:
        update["sent_count"] = data.sent_count
    if data.status == "completed":
        update["completed_at"] = datetime.utcnow().isoformat()
    supabase_admin.table("campaigns").update(update).eq("id", campaign_id).eq("user_id", user.id).execute()
    return {"message": "Updated"}

@app.get("/campaigns")
async def get_campaigns(user=Depends(get_current_user)):
    result = supabase_admin.table("campaigns").select("*").eq("user_id", user.id).order("created_at", desc=True).execute()
    campaigns = result.data or []
    if not campaigns:
        return campaigns

    # open_count/reply_count on the campaigns table itself are never updated after creation -
    # compute the real numbers live, but in bulk (2 queries total) instead of per-campaign
    # (which used to be 3 queries x N campaigns - genuinely slow once you have more than a
    # handful of campaigns, since every one of those was a separate network round-trip).
    campaign_ids = [c["id"] for c in campaigns]
    try:
        sent_rows = supabase_admin.table("emails_sent").select("campaign_id, is_opened").eq(
            "user_id", user.id
        ).in_("campaign_id", campaign_ids).execute()
        reply_rows = supabase_admin.table("replies").select("campaign_id").eq(
            "user_id", user.id
        ).in_("campaign_id", campaign_ids).execute()
    except Exception as e:
        logger.error("campaign bulk-stats failed: " + str(e))
        sent_rows = None
        reply_rows = None

    sent_counts, open_counts, reply_counts = {}, {}, {}
    for row in ((sent_rows.data if sent_rows else None) or []):
        cid = row.get("campaign_id")
        if not cid:
            continue
        sent_counts[cid] = sent_counts.get(cid, 0) + 1
        if row.get("is_opened"):
            open_counts[cid] = open_counts.get(cid, 0) + 1
    for row in ((reply_rows.data if reply_rows else None) or []):
        cid = row.get("campaign_id")
        if cid:
            reply_counts[cid] = reply_counts.get(cid, 0) + 1

    for camp in campaigns:
        cid = camp["id"]
        camp["sent_count"] = sent_counts.get(cid, 0)
        camp["open_count"] = open_counts.get(cid, 0)
        camp["reply_count"] = reply_counts.get(cid, 0)
    return campaigns

@app.delete("/campaigns/{campaign_id}")
async def delete_campaign(campaign_id: str, user=Depends(get_current_user)):
    try:
        supabase_admin.table("emails_sent").delete().eq("campaign_id", campaign_id).execute()
        supabase_admin.table("campaigns").delete().eq("id", campaign_id).eq("user_id", user.id).execute()
        return {"message": "Campaign deleted"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/campaigns/{campaign_id}/send")
async def send_campaign(campaign_id: str, background_tasks: BackgroundTasks, user=Depends(get_current_user)):
    camp = supabase_admin.table("campaigns").select("*").eq("id", campaign_id).eq("user_id", user.id).single().execute()
    if not camp.data:
        raise HTTPException(status_code=404, detail="Campaign not found")
    smtp_list = supabase_admin.table("smtp_accounts").select("*").eq("user_id", user.id).eq("is_active", True).execute()
    if not smtp_list.data:
        raise HTTPException(status_code=400, detail="No SMTP accounts found. Add one in SMTP Settings first.")
    contacts_query = supabase_admin.table("scraped_contacts").select("*").eq("user_id", user.id)
    if camp.data.get("niche"):
        niche_list = [n.strip() for n in camp.data["niche"].split(",") if n.strip()]
        if len(niche_list) == 1:
            contacts_query = contacts_query.eq("niche", niche_list[0])
        elif len(niche_list) > 1:
            contacts_query = contacts_query.in_("niche", niche_list)
    contacts = contacts_query.execute()
    contacts.data = [c for c in (contacts.data or []) if c.get("verification_status") != "invalid"]
    if not contacts.data:
        raise HTTPException(status_code=400, detail="No contacts found in this group. Use Email Scraper first.")
    background_tasks.add_task(
        send_bulk_emails,
        campaign=camp.data,
        contacts=contacts.data,
        smtp_accounts=smtp_list.data,
        user_id=user.id
    )
    supabase_admin.table("campaigns").update(
        {"status": "sending", "started_at": datetime.utcnow().isoformat()}
    ).eq("id", campaign_id).execute()
    return {"message": "Campaign started! Sending to " + str(len(contacts.data)) + " contacts.", "status": "sending"}

async def send_bulk_emails(campaign: dict, contacts: list, smtp_accounts: list, user_id: str):
    import asyncio
    smtp_idx = 0
    sent_count = 0
    for contact in contacts:
        try:
            smtp = smtp_accounts[smtp_idx % len(smtp_accounts)]
            if smtp["sent_today"] >= smtp["daily_limit"]:
                smtp_idx += 1
                if smtp_idx >= len(smtp_accounts):
                    break
                smtp = smtp_accounts[smtp_idx]
            password = decrypt_password(smtp["password_encrypted"])
            body = campaign["template_body"].replace("{{name}}", contact.get("name", "there"))
            body = body.replace("{{company}}", contact.get("company", "your company"))
            msg = MIMEMultipart("alternative")
            msg["Subject"] = campaign["subject"]
            msg["From"] = campaign.get("from_name", "") + " <" + smtp["email"] + ">"
            msg["To"] = contact["email"]
            if campaign.get("reply_to"):
                msg["Reply-To"] = campaign["reply_to"]
            tracking_id = campaign["id"] + "-" + contact["id"]
            base_url = "https://web-production-dd320.up.railway.app"
            pixel = '<img src="' + base_url + '/track/' + tracking_id + '" width="1" height="1">'
            html_body = body + "<br><br>" + pixel + "<br><small>To unsubscribe, reply UNSUBSCRIBE</small>"
            msg.attach(MIMEText(html_body, "html"))
            msg.attach(MIMEText(body + "\n\nTo unsubscribe reply UNSUBSCRIBE", "plain"))
            context = ssl.create_default_context()
            with smtplib.SMTP(smtp["host"], smtp["port"], timeout=15) as server:
                server.starttls(context=context)
                server.login(smtp["email"], password)
                server.sendmail(smtp["email"], contact["email"], msg.as_string())
            supabase_admin.table("emails_sent").insert({
                "user_id": user_id,
                "campaign_id": campaign["id"],
                "smtp_account_id": smtp["id"],
                "to_email": contact["email"],
                "to_name": contact.get("name"),
                "subject": campaign["subject"],
                "status": "sent",
                "tracking_pixel_id": tracking_id
            }).execute()
            supabase_admin.table("smtp_accounts").update(
                {"sent_today": smtp["sent_today"] + 1}
            ).eq("id", smtp["id"]).execute()
            sent_count += 1
            await asyncio.sleep(1)
        except Exception as e:
            logger.error("Failed to send to " + str(contact.get("email")) + ": " + str(e))
    supabase_admin.table("campaigns").update({
        "status": "completed",
        "sent_count": sent_count,
        "completed_at": datetime.utcnow().isoformat()
    }).eq("id", campaign["id"]).execute()

@app.get("/inbox/sent")
async def get_sent(user=Depends(get_current_user)):
    result = supabase_admin.table("emails_sent").select("*").eq("user_id", user.id).order("sent_at", desc=True).limit(100).execute()
    return result.data

@app.delete("/inbox/sent/{email_id}")
async def delete_sent_email(email_id: str, user=Depends(get_current_user)):
    supabase_admin.table("emails_sent").delete().eq("id", email_id).eq("user_id", user.id).execute()
    return {"message": "Deleted"}

class InboundReplyModel(BaseModel):
    email_id: str          # the reply+<email_id>@mailflows.org this reply was sent to
    from_email: str
    from_name: Optional[str] = None
    subject: Optional[str] = None
    text_body: Optional[str] = None
    html_body: Optional[str] = None

@app.post("/webhooks/inbound-reply")
async def inbound_reply_webhook(data: InboundReplyModel, request: Request):
    # Verify this really came from our own Cloudflare Worker, not a random POST from the internet
    secret = request.headers.get("X-Webhook-Secret", "")
    expected = os.getenv("INBOUND_WEBHOOK_SECRET", "")
    if not expected or not hmac.compare_digest(secret, expected):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    sent = supabase_admin.table("emails_sent").select("user_id, campaign_id, to_email").eq(
        "id", data.email_id
    ).single().execute()
    if not sent.data:
        # Not necessarily an error - could be an old email from before this system existed,
        # or a bounce/auto-reply we don't need to keep. Just acknowledge and drop it.
        logger.info("Inbound reply for unknown email_id " + data.email_id + " - dropped")
        return {"message": "No matching sent email - dropped"}

    body = data.text_body or data.html_body or ""
    logger.info(
        "Inbound reply received for " + data.email_id +
        " - text_body len: " + str(len(data.text_body or "")) +
        ", html_body len: " + str(len(data.html_body or "")) +
        ", stored body len: " + str(len(body))
    )
    supabase_admin.table("replies").insert({
        "user_id": sent.data["user_id"],
        "campaign_id": sent.data.get("campaign_id"),
        "from_email": data.from_email,
        "from_name": data.from_name,
        "subject": data.subject,
        "body": body,
        "is_read": False,
        "received_at": datetime.utcnow().isoformat()
    }).execute()

    return {"message": "Reply recorded"}

@app.post("/gmail/check-replies")
async def check_replies(user=Depends(get_current_user)):
    # RETIRED as of the gmail.metadata scope removal above. This endpoint used to poll
    # Gmail directly (one API round-trip per open thread, sequentially - the real cause
    # of "refresh takes minutes"), and only ever stored msg.get("snippet","") as the
    # reply body - the real cause of replies showing only a heading/first line instead
    # of the full message. The Cloudflare Email Routing + Worker webhook now delivers
    # full-body replies in real time with no polling needed, so this is now a no-op that
    # returns immediately rather than making live Gmail calls that will fail anyway for
    # any account connected after the scope change (no more metadata grant to use).
    return {"new_replies": 0, "note": "Legacy polling retired - replies now arrive automatically via webhook."}
    # --- everything below is dead code, kept only for reference / rollback ---
    sent_rows = supabase_admin.table("emails_sent").select("*").eq(
        "user_id", user.id
    ).order("sent_at", desc=True).limit(200).execute()

    rows_with_thread = [r for r in (sent_rows.data or []) if r.get("thread_id") and r.get("gmail_account_id")]
    if not rows_with_thread:
        return {"new_replies": 0}

    # Cache gmail accounts so we don't refetch per row
    account_ids = list({r["gmail_account_id"] for r in rows_with_thread})
    accounts = {}
    for aid in account_ids:
        try:
            acc = supabase_admin.table("gmail_accounts").select("*").eq(
                "id", aid
            ).eq("user_id", user.id).execute()
            if acc.data:
                accounts[aid] = acc.data[0]
        except Exception as e:
            logger.error("check_replies: could not load gmail_account " + str(aid) + ": " + str(e))
            continue

    seen_threads = set()
    new_count = 0
    import httpx

    for row in rows_with_thread:
        thread_id = row["thread_id"]
        if thread_id in seen_threads:
            continue
        seen_threads.add(thread_id)

        account = accounts.get(row["gmail_account_id"])
        if not account:
            continue

        try:
            access_token = await get_fresh_access_token(account)
            async with httpx.AsyncClient() as client:
                res = await client.get(
                    "https://gmail.googleapis.com/gmail/v1/users/me/threads/" + thread_id,
                    headers={"Authorization": "Bearer " + access_token},
                    params={"format": "metadata", "metadataHeaders": ["From", "Subject"]}
                )
            if res.status_code != 200:
                logger.error(f"check_replies: Gmail threads.get failed for thread {thread_id} - status {res.status_code}, body: {res.text[:300]}")
                continue

            thread = res.json()
            for msg in thread.get("messages", []):
                headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
                from_header = headers.get("From", "")

                # Skip messages we sent ourselves
                if account["gmail_address"].lower() in from_header.lower():
                    continue

                msg_id = msg["id"]
                existing = supabase_admin.table("replies").select("id").eq(
                    "user_id", user.id
                ).eq("gmail_message_id", msg_id).execute()
                if existing.data:
                    continue

                from_name = from_header.split("<")[0].strip().strip('"') if "<" in from_header else from_header

                supabase_admin.table("replies").insert({
                    "user_id": user.id,
                    "campaign_id": row.get("campaign_id"),
                    "from_email": from_header,
                    "from_name": from_name,
                    "subject": headers.get("Subject", ""),
                    "body": msg.get("snippet", ""),
                    "is_read": False,
                    "gmail_message_id": msg_id,
                    "received_at": datetime.utcnow().isoformat(),
                }).execute()
                new_count += 1
        except Exception as e:
            logger.error("check_replies error for thread " + thread_id + ": " + str(e))
            continue

    return {"new_replies": new_count}

@app.get("/inbox/replies/{reply_id}/suggested-reply")
async def suggested_reply(reply_id: str, user=Depends(get_current_user)):
    """Drafts a suggested follow-up reply, built from the ORIGINAL outreach email
    MailFlow already has stored (emails_sent.body), as a starting point to edit.
    NOTE: now that the Cloudflare webhook captures full reply bodies (r.get('body')),
    this could be upgraded to draft from the actual reply content instead of just the
    original outreach - not done yet, flagging for a future pass.
    """
    reply = supabase_admin.table("replies").select("*").eq("id", reply_id).eq("user_id", user.id).single().execute()
    if not reply.data:
        raise HTTPException(status_code=404, detail="Reply not found")
    r = reply.data

    original = None
    if r.get("thread_id"):
        orig_q = supabase_admin.table("emails_sent").select("subject, body, to_name, to_email").eq(
            "user_id", user.id
        ).eq("thread_id", r["thread_id"]).order("sent_at", desc=False).limit(1).execute()
        if orig_q.data:
            original = orig_q.data[0]

    contact_name = (r.get("from_name") or "there").split()[0]
    original_subject = (original or {}).get("subject") or r.get("subject") or "our previous email"

    draft = (
        f"Hi {contact_name},\n\n"
        f"Thanks for getting back to me on \"{original_subject}\" - great to hear from you.\n\n"
        f"[Add your reply here based on what they actually wrote - open the thread in Gmail "
        f"to read their message, then send from there.]\n\n"
        f"Best,\n"
    )

    groq_key = os.getenv("GROQ_API_KEY")
    ai_generated = False
    if groq_key and original and original.get("body"):
        try:
            import httpx
            async with httpx.AsyncClient(timeout=15) as client:
                gres = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {groq_key}"},
                    json={
                        "model": "llama-3.1-8b-instant",
                        "messages": [
                            {"role": "system", "content": "Write a short, friendly cold-email follow-up reply draft (under 100 words). You do NOT know what the recipient actually said back - write a generic but warm continuation based only on the original outreach email, and leave a clear placeholder for the sender to fill in specifics from the reply they can only read in Gmail."},
                            {"role": "user", "content": f"Original outreach email:\nSubject: {original_subject}\nBody: {original.get('body','')[:800]}\n\nRecipient name: {contact_name}"}
                        ],
                        "max_tokens": 200
                    }
                )
            if gres.status_code == 200:
                content = gres.json()["choices"][0]["message"]["content"].strip()
                if content:
                    draft = content
                    ai_generated = True
        except Exception as e:
            logger.error("suggested_reply Groq call failed: " + str(e))

    return {"draft": draft, "ai_generated": ai_generated, "note": "Based on your original outreach email, not the reply's actual content (MailFlow's Gmail connection can't read reply bodies)."}

@app.get("/inbox/replies")
async def get_replies(user=Depends(get_current_user)):
    result = supabase_admin.table("replies").select("*").eq("user_id", user.id).order("received_at", desc=True).execute()
    return result.data

@app.post("/inbox/replies/{reply_id}/read")
async def mark_read(reply_id: str, user=Depends(get_current_user)):
    supabase_admin.table("replies").update({"is_read": True}).eq("id", reply_id).eq("user_id", user.id).execute()
    return {"message": "Marked as read"}

@app.delete("/inbox/replies/{reply_id}")
async def delete_reply(reply_id: str, user=Depends(get_current_user)):
    supabase_admin.table("replies").delete().eq("id", reply_id).eq("user_id", user.id).execute()
    return {"message": "Deleted"}

@app.get("/track/{tracking_id}")
async def track_open(tracking_id: str):
    try:
        supabase_admin.table("emails_sent").update({
            "is_opened": True,
            "opened_at": datetime.utcnow().isoformat()
        }).eq("tracking_pixel_id", tracking_id).execute()
    except Exception:
        pass
    from fastapi.responses import Response
    pixel = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
    return Response(content=pixel, media_type="image/gif")

class AnnouncementModel(BaseModel):
    title: str
    body: str = ""
    media_url: Optional[str] = None
    media_type: Optional[str] = None  # 'image', 'video', or None

@app.get("/announcements")
async def get_announcements(user=Depends(get_current_user)):
    result = supabase_admin.table("announcements").select("*").order("created_at", desc=True).limit(30).execute()
    return result.data or []

@app.post("/admin/announcements/upload")
async def upload_announcement_media(file: UploadFile = File(...), user=Depends(require_admin_locked)):
    try:
        contents = await file.read()
        max_size = 20 * 1024 * 1024  # 20MB cap
        if len(contents) > max_size:
            raise HTTPException(status_code=400, detail="File too large - max 20MB")

        ext = (file.filename or "upload").split(".")[-1].lower()
        file_path = f"{uuid.uuid4()}.{ext}"

        supabase_admin.storage.from_("announcement-media").upload(
            file_path, contents, {"content-type": file.content_type or "application/octet-stream"}
        )
        public_url = supabase_admin.storage.from_("announcement-media").get_public_url(file_path)
        media_type = "video" if (file.content_type or "").startswith("video") else "image"
        return {"url": public_url, "media_type": media_type}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail="Upload failed: " + str(e))

@app.post("/admin/announcements")
async def create_announcement(data: AnnouncementModel, user=Depends(require_admin_locked)):
    result = supabase_admin.table("announcements").insert({
        "title": data.title,
        "body": data.body,
        "media_url": data.media_url,
        "media_type": data.media_type,
        "created_by": user.email
    }).execute()
    return result.data[0]

@app.delete("/admin/announcements/{announcement_id}")
async def delete_announcement(announcement_id: str, user=Depends(require_admin_locked)):
    supabase_admin.table("announcements").delete().eq("id", announcement_id).execute()
    return {"message": "Announcement deleted"}

@app.get("/admin/stats")
async def admin_stats(user=Depends(require_admin_locked)):
    try:
        all_users = supabase_admin.table("users").select(
            "id, plan, scraper_used_this_month, scraper_limit, scraper_reset_month, created_at"
        ).execute()
        rows = all_users.data or []
    except Exception as e:
        logger.error("admin_stats users query failed: " + str(e))
        rows = []

    current_month = datetime.utcnow().strftime("%Y-%m")
    plan_counts = {"free": 0, "personal": 0, "corporate": 0}
    total_credits_used = 0
    for r in rows:
        plan = (r.get("plan") or "free").lower()
        plan_counts[plan] = plan_counts.get(plan, 0) + 1
        if r.get("scraper_reset_month") == current_month:
            total_credits_used += r.get("scraper_used_this_month") or 0

    revenue_ngn = plan_counts.get("personal", 0) * PLANS["personal"]["amount_ngn"] / 100 + \
                  plan_counts.get("corporate", 0) * PLANS["corporate"]["amount_ngn"] / 100
    revenue_usd = plan_counts.get("personal", 0) * PLANS["personal"]["amount_usd"] / 100 + \
                  plan_counts.get("corporate", 0) * PLANS["corporate"]["amount_usd"] / 100

    # One-off revenue: scraper credit top-ups and in-depth-search (Findymail) top-ups.
    # These are real, already-collected payments and were previously left out of the
    # revenue total entirely - only recurring plan subscriptions were counted.
    topup_ngn = 0
    topup_usd = 0
    try:
        current_month_start = datetime.utcnow().strftime("%Y-%m-01")
        topup_payments = supabase_admin.table("payments").select(
            "amount, currency, plan, status, created_at"
        ).eq("status", "success").gte("created_at", current_month_start).execute()
        for p in (topup_payments.data or []):
            ptype = (p.get("plan") or "")
            if ptype.startswith("credit_topup") or ptype.startswith("indepth_search") or ptype.startswith("verification_credit_topup"):
                amt = (p.get("amount") or 0) / 100
                if (p.get("currency") or "NGN").upper() == "NGN":
                    topup_ngn += amt
                else:
                    topup_usd += amt
    except Exception as e:
        logger.error("admin_stats topup revenue query failed: " + str(e))

    revenue_ngn += topup_ngn
    revenue_usd += topup_usd

    max_possible_credits = plan_counts.get("free", 0) * 4 + \
                            plan_counts.get("personal", 0) * 100 + \
                            plan_counts.get("corporate", 0) * 500

    try:
        total_contacts = supabase_admin.table("scraped_contacts").select("id", count="exact").execute()
        contacts_count = total_contacts.count or 0
    except Exception:
        contacts_count = 0
    try:
        total_sent = supabase_admin.table("emails_sent").select("id", count="exact").execute()
        sent_count = total_sent.count or 0
    except Exception:
        sent_count = 0
    try:
        total_replies = supabase_admin.table("replies").select("id", count="exact").execute()
        replies_count = total_replies.count or 0
    except Exception:
        replies_count = 0

    return {
        "total_users": len(rows),
        "plan_breakdown": plan_counts,
        "revenue_ngn_monthly": revenue_ngn,
        "revenue_usd_monthly": revenue_usd,
        "scraper_credits_used_this_month": total_credits_used,
        "scraper_credits_max_possible": max_possible_credits,
        "total_contacts": contacts_count,
        "total_emails_sent": sent_count,
        "total_replies": replies_count
    }

@app.get("/admin/users")
async def admin_list_users(user=Depends(require_admin_locked)):
    result = supabase_admin.table("users").select(
        "id, email, full_name, plan, scraper_used_this_month, scraper_limit, created_at"
    ).order("created_at", desc=True).execute()
    return result.data

@app.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, user=Depends(require_admin_locked)):
    try:
        for table in ["replies", "emails_sent", "campaigns", "scraped_contacts", "smtp_accounts", "payments"]:
            try:
                supabase_admin.table(table).delete().eq("user_id", user_id).execute()
            except Exception:
                pass
        supabase_admin.table("users").delete().eq("id", user_id).execute()
        supabase_admin.auth.admin.delete_user(user_id)
        return {"message": "User deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ══ SUPPORT TICKETS ══
# Requires two new Supabase tables (run once in the SQL Editor):
#
# create table support_tickets (
#   id uuid primary key default gen_random_uuid(),
#   user_id uuid references users(id) on delete cascade,
#   user_email text,
#   subject text not null,
#   status text default 'open',  -- open | answered | closed
#   created_at timestamptz default now(),
#   updated_at timestamptz default now()
# );
# create table support_messages (
#   id uuid primary key default gen_random_uuid(),
#   ticket_id uuid references support_tickets(id) on delete cascade,
#   sender text not null,  -- 'user' | 'admin'
#   body text not null,
#   created_at timestamptz default now()
# );

class SupportTicketCreate(BaseModel):
    subject: str
    message: str

class SupportMessageCreate(BaseModel):
    message: str

class SupportStatusUpdate(BaseModel):
    status: str  # open | answered | closed

@app.post("/support/tickets")
async def create_support_ticket(data: SupportTicketCreate, user=Depends(get_current_user)):
    ticket = supabase_admin.table("support_tickets").insert({
        "user_id": user.id,
        "user_email": user.email,
        "subject": data.subject.strip()[:200] or "Support request",
        "status": "open",
    }).execute()
    if not ticket.data:
        raise HTTPException(status_code=500, detail="Could not create ticket")
    ticket_id = ticket.data[0]["id"]
    supabase_admin.table("support_messages").insert({
        "ticket_id": ticket_id,
        "sender": "user",
        "body": data.message.strip(),
    }).execute()

    admin_email = os.getenv("ADMIN_EMAIL")
    if admin_email:
        await send_resend_email(
            admin_email,
            "New MailFlows support ticket: " + (data.subject.strip()[:100] or "Support request"),
            "<p>New ticket from <strong>" + user.email + "</strong>:</p>"
            "<blockquote>" + data.message.strip().replace("\n", "<br>") + "</blockquote>"
            "<p>Reply from the Admin Dashboard → Support tab.</p>"
        )

    return {"id": ticket_id, "message": "Ticket created"}

@app.get("/support/tickets")
async def list_my_support_tickets(user=Depends(get_current_user)):
    result = supabase_admin.table("support_tickets").select("*").eq(
        "user_id", user.id
    ).order("updated_at", desc=True).execute()
    return result.data or []

@app.get("/support/tickets/{ticket_id}")
async def get_support_ticket(ticket_id: str, user=Depends(get_current_user)):
    ticket = supabase_admin.table("support_tickets").select("*").eq("id", ticket_id).eq("user_id", user.id).single().execute()
    if not ticket.data:
        raise HTTPException(status_code=404, detail="Ticket not found")
    messages = supabase_admin.table("support_messages").select("*").eq(
        "ticket_id", ticket_id
    ).order("created_at", desc=False).execute()
    return {"ticket": ticket.data, "messages": messages.data or []}

@app.post("/support/tickets/{ticket_id}/reply")
async def reply_to_support_ticket(ticket_id: str, data: SupportMessageCreate, user=Depends(get_current_user)):
    ticket = supabase_admin.table("support_tickets").select("*").eq("id", ticket_id).eq("user_id", user.id).single().execute()
    if not ticket.data:
        raise HTTPException(status_code=404, detail="Ticket not found")
    supabase_admin.table("support_messages").insert({
        "ticket_id": ticket_id, "sender": "user", "body": data.message.strip()
    }).execute()
    supabase_admin.table("support_tickets").update({
        "status": "open", "updated_at": datetime.utcnow().isoformat()
    }).eq("id", ticket_id).execute()

    admin_email = os.getenv("ADMIN_EMAIL")
    if admin_email:
        await send_resend_email(
            admin_email,
            "New reply on MailFlows support ticket: " + (ticket.data.get("subject") or ""),
            "<p><strong>" + user.email + "</strong> replied:</p>"
            "<blockquote>" + data.message.strip().replace("\n", "<br>") + "</blockquote>"
            "<p>Reply from the Admin Dashboard → Support tab.</p>"
        )

    return {"message": "Reply added"}

@app.get("/admin/support-tickets")
async def admin_list_support_tickets(user=Depends(require_admin_locked)):
    result = supabase_admin.table("support_tickets").select("*").order("updated_at", desc=True).execute()
    return result.data or []

@app.get("/admin/support-tickets/{ticket_id}")
async def admin_get_support_ticket(ticket_id: str, user=Depends(require_admin_locked)):
    ticket = supabase_admin.table("support_tickets").select("*").eq("id", ticket_id).single().execute()
    if not ticket.data:
        raise HTTPException(status_code=404, detail="Ticket not found")
    messages = supabase_admin.table("support_messages").select("*").eq(
        "ticket_id", ticket_id
    ).order("created_at", desc=False).execute()
    return {"ticket": ticket.data, "messages": messages.data or []}

@app.post("/admin/support-tickets/{ticket_id}/reply")
async def admin_reply_support_ticket(ticket_id: str, data: SupportMessageCreate, user=Depends(require_admin_locked)):
    ticket = supabase_admin.table("support_tickets").select("*").eq("id", ticket_id).single().execute()
    if not ticket.data:
        raise HTTPException(status_code=404, detail="Ticket not found")
    supabase_admin.table("support_messages").insert({
        "ticket_id": ticket_id, "sender": "admin", "body": data.message.strip()
    }).execute()
    supabase_admin.table("support_tickets").update({
        "status": "answered", "updated_at": datetime.utcnow().isoformat()
    }).eq("id", ticket_id).execute()

    # Notify the user by email so they aren't just waiting silently in-app.
    user_email = ticket.data.get("user_email")
    if user_email:
        await send_resend_email(
            user_email,
            "Reply to your MailFlows support ticket: " + (ticket.data.get("subject") or ""),
            "<p>Hi,</p><p>We replied to your support ticket:</p>"
            "<blockquote>" + data.message.strip().replace("\n", "<br>") + "</blockquote>"
            "<p>Log in to MailFlows and open Support to continue the conversation.</p>"
        )
    return {"message": "Reply sent"}

@app.patch("/admin/support-tickets/{ticket_id}/status")
async def admin_update_support_status(ticket_id: str, data: SupportStatusUpdate, user=Depends(require_admin_locked)):
    if data.status not in ("open", "answered", "closed"):
        raise HTTPException(status_code=400, detail="Invalid status")
    supabase_admin.table("support_tickets").update({
        "status": data.status, "updated_at": datetime.utcnow().isoformat()
    }).eq("id", ticket_id).execute()
    return {"message": "Status updated"}

@app.get("/payments/plans")
async def get_plans():
    return {
        "free": {"name": "Free", "price_ngn": 0, "price_usd": 0, "daily_limit": 100, "contacts_limit": 500, "smtp_limit": 1, "scraper_limit": 4, "campaigns_limit": 5, "ai_personalization": False, "ads": True},
        "personal": {"name": "Personal", "price_ngn": 6500, "price_usd": 4, "daily_limit": 1200, "contacts_limit": 20000, "smtp_limit": 3, "scraper_limit": 100, "campaigns_limit": 25, "ai_personalization": True, "ads": False},
        "corporate": {"name": "Corporate", "price_ngn": 24000, "price_usd": 15, "daily_limit": 4500, "contacts_limit": 70000, "smtp_limit": 10, "scraper_limit": 500, "campaigns_limit": 50, "ai_personalization": True, "ads": False}
    }

@app.get("/payments/credit-summary")
async def get_credit_summary(user=Depends(get_current_user)):
    """Powers the small credit dashboard on the Plan & Billing page: what's left,
    and a history of what was actually bought."""
    scraper_quota = await get_scraper_quota(user.id)
    verify_quota = await get_verification_quota(user.id)
    try:
        history = supabase_admin.table("payments").select(
            "id, plan, amount, currency, status, created_at"
        ).eq("user_id", user.id).order("created_at", desc=True).limit(20).execute()
        purchases = history.data or []
    except Exception as e:
        logger.error("credit-summary history fetch failed: " + str(e))
        purchases = []

    return {
        "scraper": {
            "monthly_limit": scraper_quota["limit"],
            "monthly_used": scraper_quota["used"],
            "monthly_remaining": max(scraper_quota["limit"] - scraper_quota["used"], 0),
            "bonus_credits": scraper_quota["bonus_credits"]
        },
        "verification": {
            "monthly_limit": verify_quota["limit"],
            "monthly_used": verify_quota["used"],
            "monthly_remaining": max(verify_quota["limit"] - verify_quota["used"], 0),
            "bonus_credits": verify_quota["bonus_credits"]
        },
        "purchase_history": purchases
    }

class BuyCreditsModel(BaseModel):
    pack: str
    currency: str

@app.get("/payments/credit-packs")
async def get_credit_packs():
    return CREDIT_PACKS

@app.get("/payments/verification-credit-packs")
async def get_verification_credit_packs():
    return VERIFICATION_CREDIT_PACKS

class BuyVerificationCreditsModel(BaseModel):
    pack: str
    currency: str

@app.post("/payments/buy-verification-credits")
async def buy_verification_credits(data: BuyVerificationCreditsModel, user=Depends(get_current_user)):
    if data.pack not in VERIFICATION_CREDIT_PACKS:
        raise HTTPException(status_code=400, detail="Invalid credit pack")
    if data.currency not in ["NGN", "USD"]:
        raise HTTPException(status_code=400, detail="Invalid currency")
    pack = VERIFICATION_CREDIT_PACKS[data.pack]
    amount = pack["amount_ngn"] if data.currency == "NGN" else pack["amount_usd"]
    secret_key = os.getenv("PAYSTACK_SECRET_KEY")
    frontend_url = os.getenv("FRONTEND_URL", "https://effervescent-nasturtium-6a71c2.netlify.app")
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(
                "https://api.paystack.co/transaction/initialize",
                headers={"Authorization": "Bearer " + secret_key, "Content-Type": "application/json"},
                json={
                    "email": user.email,
                    "amount": amount,
                    "currency": data.currency,
                    "metadata": {
                        "user_id": user.id,
                        "type": "verification_credit_topup",
                        "pack": data.pack,
                        "credits": pack["credits"],
                        "currency": data.currency
                    },
                    "callback_url": frontend_url
                }
            )
        result = res.json()
        if result.get("status"):
            return {
                "payment_url": result["data"]["authorization_url"],
                "reference": result["data"]["reference"],
                "credits": pack["credits"],
                "amount": amount,
                "currency": data.currency
            }
        raise HTTPException(status_code=400, detail="Payment initiation failed")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ── Findymail "In-Depth Search" - pay for exactly the quantity you want, not fixed packs ──
def get_findymail_price_per_credit(currency: str) -> float:
    """Real Findymail cost + 2% margin. Update FINDYMAIL_COST_PER_CREDIT_USD once you know
    which of their plans you're actually on (Basic=$0.049, Starter=$0.0198, Business=$0.0166)."""
    base_cost_usd = float(os.getenv("FINDYMAIL_COST_PER_CREDIT_USD", "0.049"))
    price_usd = base_cost_usd * 1.02  # 2% margin
    if currency == "NGN":
        ngn_rate = float(os.getenv("USD_TO_NGN_RATE", "1600"))
        return round(price_usd * ngn_rate, 2)
    return round(price_usd, 4)

@app.get("/payments/indepth-search-price")
async def get_indepth_price():
    return {
        "price_per_credit_usd": get_findymail_price_per_credit("USD"),
        "price_per_credit_ngn": get_findymail_price_per_credit("NGN"),
        "min_credits": 10
    }

class BuyIndepthModel(BaseModel):
    quantity: int
    currency: str

@app.post("/payments/buy-indepth-search")
async def buy_indepth_search(data: BuyIndepthModel, user=Depends(get_current_user)):
    if data.quantity < 10:
        raise HTTPException(status_code=400, detail="Minimum purchase is 10 credits")
    if data.currency not in ["NGN", "USD"]:
        raise HTTPException(status_code=400, detail="Invalid currency")

    price_per_credit = get_findymail_price_per_credit(data.currency)
    total = round(price_per_credit * data.quantity, 2)
    amount_smallest_unit = int(total * 100)  # Paystack wants kobo/cents

    secret_key = os.getenv("PAYSTACK_SECRET_KEY")
    frontend_url = os.getenv("FRONTEND_URL", "https://stellular-panda-334622.netlify.app")
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(
                "https://api.paystack.co/transaction/initialize",
                headers={"Authorization": "Bearer " + secret_key, "Content-Type": "application/json"},
                json={
                    "email": user.email,
                    "amount": amount_smallest_unit,
                    "currency": data.currency,
                    "metadata": {
                        "user_id": user.id,
                        "type": "indepth_search_topup",
                        "credits": data.quantity,
                        "currency": data.currency
                    },
                    "callback_url": frontend_url
                }
            )
        result = res.json()
        if result.get("status"):
            return {
                "payment_url": result["data"]["authorization_url"],
                "reference": result["data"]["reference"],
                "credits": data.quantity,
                "amount": amount_smallest_unit,
                "currency": data.currency
            }
        raise HTTPException(status_code=400, detail="Payment initiation failed")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/payments/buy-credits")
async def buy_credits(data: BuyCreditsModel, user=Depends(get_current_user)):
    if data.pack not in CREDIT_PACKS:
        raise HTTPException(status_code=400, detail="Invalid credit pack")
    if data.currency not in ["NGN", "USD"]:
        raise HTTPException(status_code=400, detail="Invalid currency")
    pack = CREDIT_PACKS[data.pack]
    amount = pack["amount_ngn"] if data.currency == "NGN" else pack["amount_usd"]
    secret_key = os.getenv("PAYSTACK_SECRET_KEY")
    frontend_url = os.getenv("FRONTEND_URL", "https://effervescent-nasturtium-6a71c2.netlify.app")
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(
                "https://api.paystack.co/transaction/initialize",
                headers={"Authorization": "Bearer " + secret_key, "Content-Type": "application/json"},
                json={
                    "email": user.email,
                    "amount": amount,
                    "currency": data.currency,
                    "metadata": {
                        "user_id": user.id,
                        "type": "credit_topup",
                        "pack": data.pack,
                        "credits": pack["credits"],
                        "currency": data.currency
                    },
                    "callback_url": frontend_url
                }
            )
        result = res.json()
        if result.get("status"):
            return {
                "payment_url": result["data"]["authorization_url"],
                "reference": result["data"]["reference"],
                "credits": pack["credits"],
                "amount": amount,
                "currency": data.currency
            }
        raise HTTPException(status_code=400, detail="Payment initiation failed")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/payments/initiate")
async def initiate_payment(data: InitiatePaymentModel, user=Depends(get_current_user)):
    if data.plan not in PLANS:
        raise HTTPException(status_code=400, detail="Invalid plan")
    if data.currency not in ["NGN", "USD"]:
        raise HTTPException(status_code=400, detail="Invalid currency")
    plan = PLANS[data.plan]
    amount = plan["amount_ngn"] if data.currency == "NGN" else plan["amount_usd"]
    secret_key = os.getenv("PAYSTACK_SECRET_KEY")
    frontend_url = os.getenv("FRONTEND_URL", "https://effervescent-nasturtium-6a71c2.netlify.app")
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(
                "https://api.paystack.co/transaction/initialize",
                headers={"Authorization": "Bearer " + secret_key, "Content-Type": "application/json"},
                json={
                    "email": user.email,
                    "amount": amount,
                    "currency": data.currency,
                    "metadata": {"user_id": user.id, "plan": data.plan, "currency": data.currency},
                    "callback_url": frontend_url
                }
            )
        result = res.json()
        if result.get("status"):
            return {
                "payment_url": result["data"]["authorization_url"],
                "reference": result["data"]["reference"],
                "plan": data.plan,
                "amount": amount,
                "currency": data.currency
            }
        raise HTTPException(status_code=400, detail="Payment initiation failed")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

def _record_payment_once(user_id: str, plan_label: str, amount: int, currency: str, reference: str) -> bool:
    """Inserts a payments row for this reference. Returns True if this is the
    FIRST time we've recorded this reference (safe to grant credits/plan now),
    False if it was already recorded (already granted - do not grant again).
    Relies on payments.reference having a UNIQUE constraint in Supabase."""
    try:
        supabase_admin.table("payments").insert({
            "user_id": user_id, "plan": plan_label, "amount": amount,
            "currency": currency, "reference": reference, "status": "success"
        }).execute()
        return True
    except Exception as e:
        if "duplicate" in str(e).lower() or "unique" in str(e).lower():
            return False
        logger.error(f"_record_payment_once failed for reference {reference}: " + str(e))
        raise

@app.get("/payments/verify/{reference}")
async def verify_payment(reference: str, user=Depends(get_current_user)):
    secret_key = os.getenv("PAYSTACK_SECRET_KEY")
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(
                "https://api.paystack.co/transaction/verify/" + reference,
                headers={"Authorization": "Bearer " + secret_key}
            )
        result = res.json()
        if result.get("status") and result["data"]["status"] == "success":
            metadata = result["data"].get("metadata", {})
            amount = result["data"]["amount"]
            currency = result["data"]["currency"]

            if metadata.get("type") == "indepth_search_topup":
                credits = metadata.get("credits", 0)
                if not _record_payment_once(user.id, "indepth_search_topup", amount, currency, reference):
                    return {"message": "This payment was already processed - no changes made.", "already_processed": True}
                profile = supabase_admin.table("users").select("findymail_credits").eq("id", user.id).single().execute()
                current_credits = (profile.data or {}).get("findymail_credits") or 0
                supabase_admin.table("users").update({
                    "findymail_credits": current_credits + credits
                }).eq("id", user.id).execute()
                return {
                    "message": f"✅ {credits} in-depth search credits added!",
                    "credits_added": credits,
                    "new_balance": current_credits + credits
                }

            if metadata.get("type") == "credit_topup":
                credits = metadata.get("credits", 0)
                if not _record_payment_once(user.id, "credit_topup_" + metadata.get("pack", ""), amount, currency, reference):
                    return {"message": "This payment was already processed - no changes made.", "already_processed": True}
                try:
                    profile = supabase_admin.table("users").select("scraper_bonus_credits").eq("id", user.id).single().execute()
                    current_bonus = (profile.data or {}).get("scraper_bonus_credits") or 0
                    supabase_admin.table("users").update({
                        "scraper_bonus_credits": current_bonus + credits
                    }).eq("id", user.id).execute()
                except Exception as e:
                    logger.error(f"CREDIT GRANT FAILED after payment recorded! reference={reference} user={user.id} credits={credits} type=scraper error=" + str(e))
                    return {"message": "Payment received, but crediting your account failed - contact support with this reference: " + reference, "credit_grant_failed": True}
                return {
                    "message": f"✅ {credits} scraper credits added to your account!",
                    "credits_added": credits,
                    "new_balance": current_bonus + credits
                }

            if metadata.get("type") == "verification_credit_topup":
                credits = metadata.get("credits", 0)
                if not _record_payment_once(user.id, "verification_credit_topup_" + metadata.get("pack", ""), amount, currency, reference):
                    return {"message": "This payment was already processed - no changes made.", "already_processed": True}
                try:
                    profile = supabase_admin.table("users").select("verification_bonus_credits").eq("id", user.id).single().execute()
                    current_bonus = (profile.data or {}).get("verification_bonus_credits") or 0
                    supabase_admin.table("users").update({
                        "verification_bonus_credits": current_bonus + credits
                    }).eq("id", user.id).execute()
                except Exception as e:
                    logger.error(f"CREDIT GRANT FAILED after payment recorded! reference={reference} user={user.id} credits={credits} type=verification error=" + str(e))
                    return {"message": "Payment received, but crediting your account failed - contact support with this reference: " + reference, "credit_grant_failed": True}
                return {
                    "message": f"✅ {credits} verification credits added to your account!",
                    "credits_added": credits,
                    "new_balance": current_bonus + credits
                }

            plan = metadata.get("plan")
            if plan in PLANS:
                if not _record_payment_once(user.id, plan, amount, currency, reference):
                    return {"message": "This payment was already processed - no changes made.", "already_processed": True}
                plan_data = PLANS[plan]
                supabase_admin.table("users").update({
                    "plan": plan,
                    "daily_limit": plan_data["daily_limit"],
                    "contacts_limit": plan_data["contacts_limit"],
                    "smtp_limit": plan_data["smtp_limit"],
                    "scraper_limit": plan_data["scraper_limit"],
                    "campaigns_limit": plan_data["campaigns_limit"],
                    "plan_expires_at": (datetime.utcnow() + timedelta(days=30)).isoformat()
                }).eq("id", user.id).execute()
                return {
                    "message": "Payment successful! " + plan_data["name"] + " plan activated.",
                    "plan": plan,
                    "daily_limit": plan_data["daily_limit"],
                    "contacts_limit": plan_data["contacts_limit"],
                    "smtp_limit": plan_data["smtp_limit"],
                    "scraper_limit": plan_data["scraper_limit"],
                    "campaigns_limit": plan_data["campaigns_limit"]
                }
        raise HTTPException(status_code=400, detail="Payment verification failed")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/payments/webhook")
async def paystack_webhook(request: Request):
    secret_key = os.getenv("PAYSTACK_SECRET_KEY")
    body = await request.body()
    signature = request.headers.get("x-paystack-signature", "")
    expected = hmac.new(secret_key.encode(), body, hashlib.sha512).hexdigest()
    if signature != expected:
        return {"status": "ok"}
    try:
        event = json.loads(body)
        if event.get("event") == "charge.success":
            data = event["data"]
            metadata = data.get("metadata", {})
            user_id = metadata.get("user_id")
            reference = data.get("reference")
            amount = data.get("amount")
            currency = data.get("currency")

            if metadata.get("type") == "indepth_search_topup" and user_id and reference:
                credits = metadata.get("credits", 0)
                if _record_payment_once(user_id, "indepth_search_topup", amount, currency, reference):
                    profile = supabase_admin.table("users").select("findymail_credits").eq("id", user_id).single().execute()
                    current_credits = (profile.data or {}).get("findymail_credits") or 0
                    supabase_admin.table("users").update({
                        "findymail_credits": current_credits + credits
                    }).eq("id", user_id).execute()
                return {"status": "ok"}

            if metadata.get("type") == "credit_topup" and user_id and reference:
                credits = metadata.get("credits", 0)
                if _record_payment_once(user_id, "credit_topup_" + metadata.get("pack", ""), amount, currency, reference):
                    profile = supabase_admin.table("users").select("scraper_bonus_credits").eq("id", user_id).single().execute()
                    current_bonus = (profile.data or {}).get("scraper_bonus_credits") or 0
                    supabase_admin.table("users").update({
                        "scraper_bonus_credits": current_bonus + credits
                    }).eq("id", user_id).execute()
                return {"status": "ok"}

            if metadata.get("type") == "verification_credit_topup" and user_id and reference:
                credits = metadata.get("credits", 0)
                if _record_payment_once(user_id, "verification_credit_topup_" + metadata.get("pack", ""), amount, currency, reference):
                    profile = supabase_admin.table("users").select("verification_bonus_credits").eq("id", user_id).single().execute()
                    current_bonus = (profile.data or {}).get("verification_bonus_credits") or 0
                    supabase_admin.table("users").update({
                        "verification_bonus_credits": current_bonus + credits
                    }).eq("id", user_id).execute()
                return {"status": "ok"}

            plan = metadata.get("plan")
            if user_id and plan and plan in PLANS and reference:
                if _record_payment_once(user_id, plan, amount, currency, reference):
                    plan_data = PLANS[plan]
                    supabase_admin.table("users").update({
                        "plan": plan,
                        "daily_limit": plan_data["daily_limit"],
                        "contacts_limit": plan_data["contacts_limit"],
                        "smtp_limit": plan_data["smtp_limit"],
                        "scraper_limit": plan_data["scraper_limit"],
                        "campaigns_limit": plan_data["campaigns_limit"],
                        "plan_expires_at": (datetime.utcnow() + timedelta(days=30)).isoformat()
                    }).eq("id", user_id).execute()
    except Exception as e:
        logger.error("Webhook error: " + str(e))
    return {"status": "ok"}

class AdjustCreditsModel(BaseModel):
    user_email: str
    scraper_bonus_delta: int = 0
    verification_bonus_delta: int = 0
    reason: str

@app.post("/admin/users/adjust-credits")
async def admin_adjust_credits(data: AdjustCreditsModel, admin_user=Depends(require_admin_locked)):
    """Directly adds (or subtracts, with a negative number) bonus credits for a user.
    Unlike /admin/payments/reconcile, this does NOT check payment references at all -
    use it when a payment was already recorded (so reconcile says 'already processed')
    but the credits never actually landed, which can happen if the bonus-credit UPDATE
    step threw an exception after the payment row was already inserted."""
    user_row = supabase_admin.table("users").select(
        "id, scraper_bonus_credits, verification_bonus_credits"
    ).eq("email", data.user_email.strip().lower()).single().execute()
    if not user_row.data:
        raise HTTPException(status_code=404, detail="No user found with that email")

    user_id = user_row.data["id"]
    new_scraper_bonus = max((user_row.data.get("scraper_bonus_credits") or 0) + data.scraper_bonus_delta, 0)
    new_verification_bonus = max((user_row.data.get("verification_bonus_credits") or 0) + data.verification_bonus_delta, 0)

    supabase_admin.table("users").update({
        "scraper_bonus_credits": new_scraper_bonus,
        "verification_bonus_credits": new_verification_bonus
    }).eq("id", user_id).execute()

    logger.info(f"Admin credit adjustment for {data.user_email}: scraper {data.scraper_bonus_delta:+d} -> {new_scraper_bonus}, "
                f"verification {data.verification_bonus_delta:+d} -> {new_verification_bonus}. Reason: {data.reason}")

    return {
        "message": "Credits adjusted.",
        "scraper_bonus_credits": new_scraper_bonus,
        "verification_bonus_credits": new_verification_bonus
    }

class ReconcilePaymentModel(BaseModel):
    reference: str
    user_email: str

@app.post("/admin/payments/reconcile")
async def admin_reconcile_payment(data: ReconcilePaymentModel, admin_user=Depends(require_admin_locked)):
    """For 'I paid but got nothing' reports. Look the reference up in your Paystack
    dashboard first to confirm it's a genuine successful charge, then call this with
    the reference and the user's account email. Safe to call more than once - if
    it was already granted (by the webhook, the user's own verify call, or a
    previous run of this), it reports that and changes nothing."""
    secret_key = os.getenv("PAYSTACK_SECRET_KEY")
    user_row = supabase_admin.table("users").select("id").eq("email", data.user_email.strip().lower()).single().execute()
    if not user_row.data:
        raise HTTPException(status_code=404, detail="No user found with that email")
    user_id = user_row.data["id"]

    async with httpx.AsyncClient() as client:
        res = await client.get(
            "https://api.paystack.co/transaction/verify/" + data.reference,
            headers={"Authorization": "Bearer " + secret_key}
        )
    result = res.json()
    if not (result.get("status") and result["data"]["status"] == "success"):
        raise HTTPException(status_code=400, detail="Paystack does not show this as a successful payment")

    metadata = result["data"].get("metadata", {})
    amount = result["data"]["amount"]
    currency = result["data"]["currency"]

    if metadata.get("type") == "indepth_search_topup":
        credits = metadata.get("credits", 0)
        if not _record_payment_once(user_id, "indepth_search_topup", amount, currency, data.reference):
            return {"message": "Already processed - nothing to do.", "already_processed": True}
        profile = supabase_admin.table("users").select("findymail_credits").eq("id", user_id).single().execute()
        current = (profile.data or {}).get("findymail_credits") or 0
        supabase_admin.table("users").update({"findymail_credits": current + credits}).eq("id", user_id).execute()
        return {"message": f"Granted {credits} in-depth search credits."}

    if metadata.get("type") == "credit_topup":
        credits = metadata.get("credits", 0)
        if not _record_payment_once(user_id, "credit_topup_" + metadata.get("pack", ""), amount, currency, data.reference):
            return {"message": "Already processed - nothing to do.", "already_processed": True}
        profile = supabase_admin.table("users").select("scraper_bonus_credits").eq("id", user_id).single().execute()
        current = (profile.data or {}).get("scraper_bonus_credits") or 0
        supabase_admin.table("users").update({"scraper_bonus_credits": current + credits}).eq("id", user_id).execute()
        return {"message": f"Granted {credits} scraper credits."}

    if metadata.get("type") == "verification_credit_topup":
        credits = metadata.get("credits", 0)
        if not _record_payment_once(user_id, "verification_credit_topup_" + metadata.get("pack", ""), amount, currency, data.reference):
            return {"message": "Already processed - nothing to do.", "already_processed": True}
        profile = supabase_admin.table("users").select("verification_bonus_credits").eq("id", user_id).single().execute()
        current = (profile.data or {}).get("verification_bonus_credits") or 0
        supabase_admin.table("users").update({"verification_bonus_credits": current + credits}).eq("id", user_id).execute()
        return {"message": f"Granted {credits} verification credits."}

    plan = metadata.get("plan")
    if plan in PLANS:
        if not _record_payment_once(user_id, plan, amount, currency, data.reference):
            return {"message": "Already processed - nothing to do.", "already_processed": True}
        plan_data = PLANS[plan]
        supabase_admin.table("users").update({
            "plan": plan, "daily_limit": plan_data["daily_limit"], "contacts_limit": plan_data["contacts_limit"],
            "smtp_limit": plan_data["smtp_limit"], "scraper_limit": plan_data["scraper_limit"],
            "campaigns_limit": plan_data["campaigns_limit"],
            "plan_expires_at": (datetime.utcnow() + timedelta(days=30)).isoformat()
        }).eq("id", user_id).execute()
        return {"message": f"Activated {plan_data['name']} plan."}

    raise HTTPException(status_code=400, detail="Could not determine what this payment was for from its metadata")

# ══════════════════════════════════════════════════════════════
# GOOGLE OAUTH ROUTES — Add to bottom of main.py
# ══════════════════════════════════════════════════════════════
# pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client

import json
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "https://web-production-dd320.up.railway.app/auth/google/callback"
)
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://effervescent-nasturtium-6a71c2.netlify.app")

GMAIL_SCOPES = [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]
# gmail.metadata REMOVED. This was a leftover from an earlier attempt to dodge Google's
# CASA security review by requesting a lighter read-scope instead of gmail.readonly.
# It's no longer needed: the Cloudflare Email Routing + Worker pipeline (see
# /webhooks/inbound-reply below) captures full reply bodies without any Gmail read
# scope at all. Leaving gmail.metadata in here was actively harmful - it kept the old
# check_replies() snippet-only path alive and wired to the frontend's Refresh button,
# which is why replies sometimes showed only a short snippet/heading instead of the
# real body even though the webhook pipeline had the full text the whole time.
# gmail.send is a Sensitive scope (self-declared, no CASA). That's now the only Gmail
# scope MailFlows requests.
#
# IMPORTANT: users who connected Gmail before this change granted gmail.metadata too.
# That old grant doesn't get revoked automatically - it just stops being requested for
# new/re connections. If you want it fully gone for existing users, they'd need to
# disconnect and reconnect Gmail (or revoke access at myaccount.google.com/permissions).

class GmailAccountLabel(BaseModel):
    label: str = "Gmail"
    daily_limit: int = 490

# ── Step 1: Start Google OAuth flow ──
@app.get("/auth/google")
async def google_auth(user=Depends(get_current_user)):
    from urllib.parse import urlencode
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(GMAIL_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": user.id,  # Pass user_id as state
    }
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    return {"auth_url": auth_url}

# ── Step 2: Google redirects back here ──
@app.get("/auth/google/callback")
async def google_callback(code: str, state: str):
    from fastapi.responses import RedirectResponse
    import httpx

    # Exchange code for tokens
    try:
        async with httpx.AsyncClient() as client:
            token_res = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "redirect_uri": GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                }
            )
        token_data = token_res.json()

        if "error" in token_data:
            return RedirectResponse(
                url=FRONTEND_URL + "?gmail_error=" + token_data.get("error", "unknown")
            )

        access_token = token_data["access_token"]
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in", 3600)

        if not refresh_token:
            return RedirectResponse(
                url=FRONTEND_URL + "?gmail_error=no_refresh_token"
            )

        # Get Gmail address
        async with httpx.AsyncClient() as client:
            profile_res = await client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": "Bearer " + access_token}
            )
        profile = profile_res.json()
        gmail_address = profile.get("email")
        display_name = profile.get("name", gmail_address)

        if not gmail_address:
            return RedirectResponse(
                url=FRONTEND_URL + "?gmail_error=no_email"
            )

        # Store in database
        expires_at = (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat()
        user_id = state  # state contains user_id

        try:
            # Check if already exists
            existing = supabase_admin.table("gmail_accounts").select("id, is_active").eq(
                "user_id", user_id
            ).eq("gmail_address", gmail_address).execute()

            was_inactive = bool(existing.data) and not existing.data[0].get("is_active", True)
            is_brand_new = not existing.data

            # 10-hour cooldown: only applies when (re)activating an account that was
            # disconnected, or adding a genuinely new account. Refreshing tokens on an
            # already-active account is unaffected.
            if was_inactive or is_brand_new:
                cooldown_msg = await check_gmail_reconnect_cooldown(user_id)
                if cooldown_msg:
                    from urllib.parse import quote
                    return RedirectResponse(
                        url=FRONTEND_URL + "?gmail_error=cooldown&gmail_error_detail=" + quote(cooldown_msg)
                    )

            if existing.data:
                # Update existing
                supabase_admin.table("gmail_accounts").update({
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_expires_at": expires_at,
                    "is_active": True,
                    "display_name": display_name,
                }).eq("user_id", user_id).eq("gmail_address", gmail_address).execute()
            else:
                # Insert new
                supabase_admin.table("gmail_accounts").insert({
                    "user_id": user_id,
                    "gmail_address": gmail_address,
                    "display_name": display_name,
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_expires_at": expires_at,
                    "is_active": True,
                    "sent_today": 0,
                    "daily_limit": 490,  # stay under Gmail's real 500/day cap to reduce flagging risk
                }).execute()

        except Exception as e:
            logger.error("DB error saving Gmail token: " + str(e))
            return RedirectResponse(
                url=FRONTEND_URL + "?gmail_error=db_error"
            )

        return RedirectResponse(
            url=FRONTEND_URL + "?gmail_connected=" + gmail_address
        )

    except Exception as e:
        logger.error("OAuth callback error: " + str(e))
        return RedirectResponse(
            url=FRONTEND_URL + "?gmail_error=callback_failed"
        )

# ── Step 3: List connected Gmail accounts ──
@app.get("/gmail/accounts")
async def list_gmail_accounts(user=Depends(get_current_user)):
    result = supabase_admin.table("gmail_accounts").select(
        "id, gmail_address, display_name, is_active, sent_today, daily_limit, last_used_at, last_reset_date, created_at"
    ).eq("user_id", user.id).execute()
    accounts = await reset_gmail_daily_counts(result.data or [])
    return accounts

# ── Step 4: Delete Gmail account ──
GMAIL_RECONNECT_COOLDOWN_HOURS = 10

@app.delete("/gmail/accounts/{account_id}")
async def delete_gmail_account(account_id: str, user=Depends(get_current_user)):
    # Soft-delete only - deactivate but keep sent_today history intact.
    # A hard delete would let someone disconnect+reconnect to reset their daily
    # counter, silently letting real usage exceed the safe limit without us knowing.
    supabase_admin.table("gmail_accounts").update({
        "is_active": False,
        "disconnected_at": datetime.utcnow().isoformat(),
    }).eq("id", account_id).eq("user_id", user.id).execute()
    return {"message": "Gmail account disconnected"}


async def check_gmail_reconnect_cooldown(user_id: str) -> Optional[str]:
    """Returns an error message if this user disconnected ANY Gmail account within the
    last GMAIL_RECONNECT_COOLDOWN_HOURS, else None. Blocks both reactivating the same
    account and connecting a brand-new one during the cooldown, so someone can't
    disconnect+reconnect (same or different address) to reset daily counters or dodge
    per-account limits."""
    recent = supabase_admin.table("gmail_accounts").select("disconnected_at").eq(
        "user_id", user_id
    ).eq("is_active", False).not_.is_("disconnected_at", "null").order(
        "disconnected_at", desc=True
    ).limit(1).execute()
    if not recent.data:
        return None
    last = recent.data[0].get("disconnected_at")
    if not last:
        return None
    disconnected_at = datetime.fromisoformat(last.replace("Z", "+00:00")) if "Z" in last else datetime.fromisoformat(last)
    if disconnected_at.tzinfo is not None:
        disconnected_at = disconnected_at.replace(tzinfo=None)
    elapsed_hours = (datetime.utcnow() - disconnected_at).total_seconds() / 3600
    if elapsed_hours < GMAIL_RECONNECT_COOLDOWN_HOURS:
        remaining = round(GMAIL_RECONNECT_COOLDOWN_HOURS - elapsed_hours, 1)
        return f"You disconnected a Gmail account recently. For accurate sending counts, you can't connect or reconnect a Gmail account for {remaining} more hour(s)."
    return None

# ── Helper: Get fresh access token ──
async def get_fresh_access_token(account: dict) -> str:
    import httpx
    # Check if current token is still valid
    if account.get("token_expires_at"):
        expires_at = datetime.fromisoformat(
            account["token_expires_at"].replace("Z", "+00:00")
        )
        if expires_at > datetime.now(expires_at.tzinfo) + timedelta(minutes=5):
            return account["access_token"]

    # Refresh the token
    async with httpx.AsyncClient() as client:
        res = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "refresh_token": account["refresh_token"],
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "grant_type": "refresh_token",
            }
        )
    data = res.json()

    if "error" in data:
        raise Exception("Token refresh failed: " + data.get("error", "unknown"))

    new_access_token = data["access_token"]
    new_expires_at = (
        datetime.utcnow() + timedelta(seconds=data.get("expires_in", 3600))
    ).isoformat()

    # Update in database
    supabase_admin.table("gmail_accounts").update({
        "access_token": new_access_token,
        "token_expires_at": new_expires_at,
    }).eq("id", account["id"]).execute()

    return new_access_token

# ── Helper: Send email via Gmail API ──
async def reset_gmail_daily_counts(accounts: list) -> list:
    """Gmail's daily send limit resets every day - but sent_today never did on our side.
    This checks each account's last reset date and zeroes the counter if a new day started."""
    today = datetime.utcnow().strftime("%Y-%m-%d")
    updated = []
    for acc in accounts:
        if acc.get("last_reset_date") != today:
            supabase_admin.table("gmail_accounts").update({
                "sent_today": 0,
                "last_reset_date": today
            }).eq("id", acc["id"]).execute()
            acc["sent_today"] = 0
            acc["last_reset_date"] = today
        updated.append(acc)
    return updated

async def check_plan_daily_limit(user_id: str) -> dict:
    """Your plan promises a certain number of emails/day (e.g. Personal = 1200).
    This checks today's real total across all your connected Gmail accounts against that promise."""
    profile = supabase_admin.table("users").select("daily_limit").eq("id", user_id).single().execute()
    plan_limit = (profile.data or {}).get("daily_limit") or 100

    accounts = supabase_admin.table("gmail_accounts").select(
        "id, sent_today, last_reset_date"
    ).eq("user_id", user_id).eq("is_active", True).execute()
    accounts_data = await reset_gmail_daily_counts(accounts.data or [])
    total_sent_today = sum(a.get("sent_today", 0) for a in accounts_data)

    if total_sent_today >= plan_limit:
        return {
            "ok": False,
            "message": f"You've reached your plan's daily sending limit ({total_sent_today}/{plan_limit}). Upgrade your plan or try again tomorrow.",
            "sent_today": total_sent_today,
            "limit": plan_limit
        }
    return {"ok": True, "sent_today": total_sent_today, "limit": plan_limit}

async def send_via_gmail_api(
    account: dict,
    to_email: str,
    subject: str,
    html_body: str,
    plain_body: str,
    from_name: str = None,
    reply_to: str = None,
    thread_id: str = None
) -> dict:
    access_token = await get_fresh_access_token(account)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = (from_name or account["display_name"] or account["gmail_address"]) + \
                  " <" + account["gmail_address"] + ">"
    msg["To"] = to_email
    if reply_to:
        msg["Reply-To"] = reply_to

    msg.attach(MIMEText(plain_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    payload = {"raw": raw}
    if thread_id:
        payload["threadId"] = thread_id

    import httpx
    async with httpx.AsyncClient() as client:
        res = await client.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers={
                "Authorization": "Bearer " + access_token,
                "Content-Type": "application/json",
            },
            json=payload
        )

    if res.status_code not in [200, 202]:
        raise Exception("Gmail API error: " + res.text)

    send_result = res.json()

    # Update sent count
    supabase_admin.table("gmail_accounts").update({
        "sent_today": account["sent_today"] + 1,
        "last_used_at": datetime.utcnow().isoformat(),
    }).eq("id", account["id"]).execute()

    return {"message_id": send_result.get("id"), "thread_id": send_result.get("threadId")}

# ── Step 5: Send test email via Gmail API ──
class GmailTestModel(BaseModel):
    account_id: str
    to_email: str
    subject: str = "Test Email from MailFlows"

# ── Send single custom email via Gmail API (used by Quick Send) ──
class GmailSendModel(BaseModel):
    account_id: str
    to_email: str
    subject: str
    body: str
    from_name: str = None

class GenerateEmailModel(BaseModel):
    context: str
    tone: Optional[str] = "professional"

@app.post("/ai/generate-email")
async def generate_email(data: GenerateEmailModel, user=Depends(get_current_user)):
    try:
        profile = supabase_admin.table("users").select("plan").eq("id", user.id).single().execute()
        plan = (profile.data.get("plan") or "free").lower() if profile.data else "free"
    except Exception:
        plan = "free"
    if plan == "free":
        raise HTTPException(
            status_code=403,
            detail="AI email writing is a Personal/Corporate plan feature. Upgrade in Plan & Billing to use it."
        )

    gemini_key = os.getenv("GEMINI_API_KEY")
    if not gemini_key:
        raise HTTPException(status_code=400, detail="AI writing assistant isn't set up yet - add GEMINI_API_KEY in Railway.")

    system_prompt = (
        "You write emails based on the user's description. Follow their instruction LITERALLY and "
        "proportionally to what they actually asked for. If they ask for something simple - a greeting, "
        "a short thank-you, a one-line follow-up - write exactly that, short and plain. Do NOT expand a "
        "simple request into a cold-outreach sales pitch unless the user's description actually describes "
        "a product, service, offer, or target audience to pitch to. Only write full cold-email-style "
        "content (introducing yourself, describing what you do, asking about their priorities) when the "
        "user's description genuinely calls for that. "
        "When cold-outreach content IS appropriate: keep it concise (under 120 words), warm but "
        "professional, no corporate jargon, no excessive exclamation points. Vary your opening line, "
        "structure, and phrasing so it doesn't read like a rigid template - imagine a different real "
        "person wrote it each time. Avoid dead cliches like 'I hope this email finds you well' or "
        "'I wanted to reach out'. Avoid overused AI-sounding buzzwords: streamline, leverage, unlock, "
        "elevate, seamless, cutting-edge, game-changer, robust, synergy, in today's fast-paced world. "
        "Use plain, everyday words a real person would actually say out loud. Vary sentence length - "
        "mix short punchy sentences with longer ones, the way real writing naturally sounds. "
        "Personalization tags like {{name}} or {{company}} may be used only where they make sense for "
        "what was actually asked. "
        "CRITICAL RULE - NEVER INVENT FACTS: only mention details about the recipient, their company, "
        "their location, their website, or their business that the user's description explicitly states. "
        "Never guess or make up specifics like where they're based, what they import/export, what their "
        "website looks like, their industry practices, or anything else not directly given to you. A "
        "vague but honest email is always correct; a specific but fabricated one is never acceptable, "
        "since it will be sent to a real person and false claims damage trust and deliverability. "
        "Respond ONLY in this exact format, nothing else, no preamble:\n"
        "SUBJECT: <subject line>\n"
        "BODY: <email body>"
    )
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            res = await client.post(
                "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent",
                headers={"x-goog-api-key": gemini_key, "Content-Type": "application/json"},
                json={
                    "contents": [
                        {"parts": [{"text": system_prompt + "\n\nTone: " + data.tone + ". Context: " + data.context}]}
                    ],
                    "generationConfig": {"temperature": 1.0}
                }
            )
        if res.status_code != 200:
            raise HTTPException(status_code=400, detail="AI generation failed: " + res.text[:200])

        content = res.json()["candidates"][0]["content"]["parts"][0]["text"]
        subject, body = "", content.strip()
        if "SUBJECT:" in content and "BODY:" in content:
            subject = content.split("SUBJECT:")[1].split("BODY:")[0].strip()
            body = content.split("BODY:")[1].strip()

        return {"subject": subject, "body": body}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail="AI generation error: " + str(e))

class FaqChatModel(BaseModel):
    message: str
    history: Optional[List[dict]] = None

FAQ_SYSTEM_PROMPT = (
    "You are the in-app support assistant for MailFlows, a cold email SaaS platform. "
    "Answer the user's question directly and briefly (2-5 sentences unless they ask for more detail). "
    "You can help with two kinds of questions: (1) how to use MailFlows itself, and (2) general "
    "cold email writing / outreach strategy advice.\n\n"
    "Facts about MailFlows you can rely on:\n"
    "- Users connect their own Gmail account via OAuth (Settings > SMTP Settings) - MailFlows sends "
    "through that Gmail account, not its own servers.\n"
    "- Plans: Free (100 emails/day, 500 contacts, 4 scraper credits/month, no AI), "
    "Personal ($4/N6,500 - 1,200 emails/day, 20,000 contacts, 100 scraper credits/month, AI personalization), "
    "Corporate ($15/N24,000 - 4,500 emails/day, 70,000 contacts, 500 scraper credits/month, AI personalization).\n"
    "- 1 scraper credit = 1 real email address actually found, not 1 search - searching costs nothing if it finds no results.\n"
    "- Email verification also has a monthly allowance matching the scraper credit number above, and resets monthly - "
    "unlike scraping, verification allowance can't be extended by buying bonus credits.\n"
    "- Contacts can be added manually, pasted in bulk, or found with the Email Scraper (searches company "
    "websites for public business emails).\n"
    "- Email verification checks if an address is real/deliverable before you send to it.\n"
    "- Campaigns can target a specific contact group/niche, and send from multiple connected Gmail accounts "
    "which auto-rotate when one hits its daily limit.\n"
    "- Sent Emails and Replies are kept for 90 days then automatically deleted.\n"
    "- Replies only shows genuine replies to emails that were sent through MailFlows via a connected Gmail "
    "account - it does not read your whole Gmail inbox.\n"
    "- The '✨ Generate with AI' button drafts a subject and body from a short description.\n\n"
    "If you don't know the answer, say so honestly and suggest they contact support. "
    "Never make up pricing, limits, or features not listed above."
)

@app.post("/ai/faq-chat")
async def faq_chat(data: FaqChatModel, user=Depends(get_current_user)):
    gemini_key = os.getenv("GEMINI_API_KEY")
    if not gemini_key:
        raise HTTPException(status_code=400, detail="Chat assistant isn't set up yet - add GEMINI_API_KEY in Railway.")

    contents = []
    for turn in (data.history or [])[-10:]:
        role = "user" if turn.get("role") == "user" else "model"
        text = turn.get("text", "")
        if text:
            contents.append({"role": role, "parts": [{"text": text}]})
    contents.append({"role": "user", "parts": [{"text": data.message}]})

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            res = await client.post(
                "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent",
                headers={"x-goog-api-key": gemini_key, "Content-Type": "application/json"},
                json={
                    "system_instruction": {"parts": [{"text": FAQ_SYSTEM_PROMPT}]},
                    "contents": contents
                }
            )
        if res.status_code != 200:
            raise HTTPException(status_code=400, detail="Chat failed: " + res.text[:200])
        reply = res.json()["candidates"][0]["content"]["parts"][0]["text"]
        return {"reply": reply.strip()}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail="Chat error: " + str(e))

class SendReplyModel(BaseModel):
    account_id: str
    to_email: str
    subject: str
    body: str

@app.post("/gmail/send-reply")
async def gmail_send_reply(data: SendReplyModel, user=Depends(get_current_user)):
    """Sends a reply through MailFlows (not an external Gmail compose window), so it
    carries its own fresh reply+ tracking address - meaning if the contact replies
    again, that gets captured too, keeping an ongoing conversation fully visible
    instead of only ever catching the first reply."""
    account_rec = supabase_admin.table("gmail_accounts").select("*").eq(
        "id", data.account_id
    ).eq("user_id", user.id).single().execute()

    if not account_rec.data:
        raise HTTPException(status_code=404, detail="Gmail account not found")

    account = account_rec.data
    account = (await reset_gmail_daily_counts([account]))[0]

    if account["sent_today"] >= account["daily_limit"]:
        raise HTTPException(
            status_code=403,
            detail=f"This Gmail account has hit its daily limit ({account['sent_today']}/{account['daily_limit']}). Connect another account or try again tomorrow."
        )

    plan_check = await check_plan_daily_limit(user.id)
    if not plan_check["ok"]:
        raise HTTPException(status_code=403, detail=plan_check["message"])

    html_body = data.body.replace("\n", "<br>")
    email_id = str(uuid.uuid4())
    tracking_reply_to = account["gmail_address"] + ", reply+" + email_id + "@mailflows.org"

    try:
        send_result = await send_via_gmail_api(
            account=account,
            to_email=data.to_email,
            subject=data.subject,
            html_body=html_body,
            plain_body=data.body,
            reply_to=tracking_reply_to,
        )
        supabase_admin.table("emails_sent").insert({
            "id": email_id,
            "user_id": user.id,
            "campaign_id": None,
            "to_email": data.to_email,
            "to_name": None,
            "subject": data.subject,
            "body": data.body,
            "status": "sent",
            "thread_id": send_result.get("thread_id"),
            "gmail_account_id": account["id"],
        }).execute()
        return {"message": "Reply sent to " + data.to_email, "status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Send failed: " + str(e))

@app.post("/gmail/send")
async def gmail_send(data: GmailSendModel, user=Depends(get_current_user)):
    account_rec = supabase_admin.table("gmail_accounts").select("*").eq(
        "id", data.account_id
    ).eq("user_id", user.id).single().execute()

    if not account_rec.data:
        raise HTTPException(status_code=404, detail="Gmail account not found")

    account = account_rec.data
    account = (await reset_gmail_daily_counts([account]))[0]

    if account["sent_today"] >= account["daily_limit"]:
        raise HTTPException(
            status_code=403,
            detail=f"This Gmail account has hit its daily limit ({account['sent_today']}/{account['daily_limit']}). Connect another account or try again tomorrow."
        )

    plan_check = await check_plan_daily_limit(user.id)
    if not plan_check["ok"]:
        raise HTTPException(status_code=403, detail=plan_check["message"])

    html_body = data.body.replace("\n", "<br>")
    email_id = str(uuid.uuid4())
    tracking_reply_to = account["gmail_address"] + ", reply+" + email_id + "@mailflows.org"

    try:
        send_result = await send_via_gmail_api(
            account=account,
            to_email=data.to_email,
            subject=data.subject,
            html_body=html_body,
            plain_body=data.body,
            from_name=data.from_name,
            reply_to=tracking_reply_to,
        )
        supabase_admin.table("emails_sent").insert({
            "id": email_id,
            "user_id": user.id,
            "campaign_id": None,
            "to_email": data.to_email,
            "to_name": None,
            "subject": data.subject,
            "body": data.body,
            "status": "sent",
            "thread_id": send_result.get("thread_id"),
            "gmail_account_id": account["id"],
        }).execute()
        return {"message": "Email sent successfully to " + data.to_email, "status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Gmail send failed: " + str(e))

@app.post("/gmail/test")
async def test_gmail(data: GmailTestModel, user=Depends(get_current_user)):
    account_rec = supabase_admin.table("gmail_accounts").select("*").eq(
        "id", data.account_id
    ).eq("user_id", user.id).single().execute()

    if not account_rec.data:
        raise HTTPException(status_code=404, detail="Gmail account not found")

    account = account_rec.data
    try:
        await send_via_gmail_api(
            account=account,
            to_email=data.to_email,
            subject=data.subject,
            html_body="<h2 style='color:#00d4aa'>MailFlows Test Email</h2><p>Your Gmail is connected and working!</p>",
            plain_body="MailFlows Test Email - Your Gmail is connected and working!",
        )
        return {"message": "Test email sent successfully to " + data.to_email, "status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Gmail send failed: " + str(e))

# ── Step 6: Send campaign via Gmail API ──
@app.post("/gmail/campaigns/{campaign_id}/send")
async def send_gmail_campaign(
    campaign_id: str,
    background_tasks: BackgroundTasks,
    user=Depends(get_current_user)
):
    camp = supabase_admin.table("campaigns").select("*").eq(
        "id", campaign_id
    ).eq("user_id", user.id).single().execute()
    if not camp.data:
        raise HTTPException(status_code=404, detail="Campaign not found")

    gmail_accounts = supabase_admin.table("gmail_accounts").select("*").eq(
        "user_id", user.id
    ).eq("is_active", True).execute()
    if not gmail_accounts.data:
        raise HTTPException(
            status_code=400,
            detail="No Gmail accounts connected. Go to SMTP Settings and click Connect Gmail."
        )

    gmail_accounts.data = await reset_gmail_daily_counts(gmail_accounts.data)

    plan_check = await check_plan_daily_limit(user.id)
    if not plan_check["ok"]:
        raise HTTPException(status_code=403, detail=plan_check["message"])

    contacts_query = supabase_admin.table("scraped_contacts").select("*").eq("user_id", user.id)
    if camp.data.get("niche"):
        niche_list = [n.strip() for n in camp.data["niche"].split(",") if n.strip()]
        if len(niche_list) == 1:
            contacts_query = contacts_query.eq("niche", niche_list[0])
        elif len(niche_list) > 1:
            contacts_query = contacts_query.in_("niche", niche_list)
    contacts = contacts_query.execute()
    contacts.data = [c for c in (contacts.data or []) if c.get("verification_status") != "invalid"]
    if not contacts.data:
        raise HTTPException(
            status_code=400,
            detail="No contacts found in this group. Use Email Scraper or Add Contact first."
        )

    background_tasks.add_task(
        send_bulk_via_gmail,
        campaign=camp.data,
        contacts=contacts.data,
        gmail_accounts=gmail_accounts.data,
        user_id=user.id
    )

    supabase_admin.table("campaigns").update({
        "status": "sending",
        "started_at": datetime.utcnow().isoformat()
    }).eq("id", campaign_id).execute()

    return {
        "message": "Campaign started! Sending to " + str(len(contacts.data)) + " contacts via Gmail API.",
        "status": "sending"
    }

async def send_bulk_via_gmail(
    campaign: dict,
    contacts: list,
    gmail_accounts: list,
    user_id: str
):
    import asyncio
    import random
    account_idx = 0
    sent_count = 0

    for contact in contacts:
        try:
            plan_check = await check_plan_daily_limit(user_id)
            if not plan_check["ok"]:
                logger.info("Campaign stopped: plan daily limit reached (" + str(plan_check["sent_today"]) + "/" + str(plan_check["limit"]) + ")")
                break

            # Rotate accounts when limit hit
            account = gmail_accounts[account_idx % len(gmail_accounts)]
            if account["sent_today"] >= account["daily_limit"]:
                account_idx += 1
                if account_idx >= len(gmail_accounts):
                    logger.info("All Gmail accounts hit daily limit")
                    break
                account = gmail_accounts[account_idx]

            # Personalize body
            body = campaign["template_body"].replace(
                "{{name}}", contact.get("name", "there")
            ).replace(
                "{{company}}", contact.get("company", "your company")
            )

            tracking_id = campaign["id"] + "-" + contact["id"]
            base_url = "https://web-production-dd320.up.railway.app"
            pixel = '<img src="' + base_url + '/track/' + tracking_id + '" width="1" height="1">'
            html_body = body + "<br><br>" + pixel + \
                        "<br><small>To unsubscribe, reply UNSUBSCRIBE</small>"
            plain_body = body + "\n\nTo unsubscribe reply UNSUBSCRIBE"

            # Every sent email gets its own reply-to address on our own domain
            # (reply+<email_id>@mailflows.org). This is how replies get matched back
            # without ever needing to read the user's Gmail inbox.
            email_id = str(uuid.uuid4())
            tracking_reply_to = account["gmail_address"] + ", reply+" + email_id + "@mailflows.org"

            send_result = await send_via_gmail_api(
                account=account,
                to_email=contact["email"],
                subject=campaign["subject"],
                html_body=html_body,
                plain_body=plain_body,
                from_name=campaign.get("from_name"),
                reply_to=tracking_reply_to,
            )

            # Log sent email
            supabase_admin.table("emails_sent").insert({
                "id": email_id,
                "user_id": user_id,
                "campaign_id": campaign["id"],
                "to_email": contact["email"],
                "to_name": contact.get("name"),
                "subject": campaign["subject"],
                "body": plain_body,
                "status": "sent",
                "tracking_pixel_id": tracking_id,
                "thread_id": send_result.get("thread_id"),
                "gmail_account_id": account["id"],
            }).execute()

            # Update account sent count in memory
            account["sent_today"] = account.get("sent_today", 0) + 1
            sent_count += 1

            # Smart delay - randomized 3-8s between emails to avoid spam pattern detection
            await asyncio.sleep(random.uniform(3, 8))

        except Exception as e:
            logger.error(
                "Failed to send to " + str(contact.get("email")) + ": " + str(e)
            )

    supabase_admin.table("campaigns").update({
        "status": "completed",
        "sent_count": sent_count,
        "completed_at": datetime.utcnow().isoformat()
    }).eq("id", campaign["id"]).execute()

    logger.info("Campaign done. Sent: " + str(sent_count))
