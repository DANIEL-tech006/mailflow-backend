from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import os, smtplib, ssl, logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from supabase import create_client, Client
from cryptography.fernet import Fernet
import base64, hashlib

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="MailFlow API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Supabase
supabase: Client = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_ANON_KEY")
)

supabase_admin: Client = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_SERVICE_KEY")
)

security = HTTPBearer()

# Encryption for SMTP passwords
def get_cipher():
    key = os.getenv("ENCRYPTION_KEY", "")
    if not key:
        key = base64.urlsafe_b64encode(hashlib.sha256(b"mailflow-default-key").digest()).decode()
    return Fernet(key.encode() if len(key) < 44 else key.encode())

def encrypt_password(password: str) -> str:
    return get_cipher().encrypt(password.encode()).decode()

def decrypt_password(encrypted: str) -> str:
    return get_cipher().decrypt(encrypted.encode()).decode()

# ── AUTH HELPER ──
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        user = supabase.auth.get_user(credentials.credentials)
        if not user or not user.user:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user.user
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# ── MODELS ──
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

class SendTestModel(BaseModel):
    smtp_id: str
    to_email: str
    subject: str = "Test Email from MailFlow"

class ScrapeModel(BaseModel):
    niche: str
    limit: int = 25

# ══════════════════════════════
# AUTH ROUTES
# ══════════════════════════════

@app.get("/")
def root():
    return {"message": "MailFlow API v2.0 running", "status": "ok"}

@app.post("/auth/register")
async def register(data: RegisterModel):
    try:
        res = supabase.auth.sign_up({
            "email": data.email,
            "password": data.password,
            "options": {"data": {"full_name": data.full_name}}
        })
        if res.user:
            supabase_admin.table("users").insert({
                "id": res.user.id,
                "email": data.email,
                "full_name": data.full_name,
                "plan": "free",
                "daily_limit": 500,
                "emails_sent_today": 0
            }).execute()
            return {"message": "Account created. Check your email to verify.", "user_id": res.user.id}
        raise HTTPException(status_code=400, detail="Registration failed")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/auth/login")
async def login(data: LoginModel):
    try:
        res = supabase.auth.sign_in_with_password({"email": data.email, "password": data.password})
        if res.user:
            profile = supabase_admin.table("users").select("*").eq("id", res.user.id).single().execute()
            return {
                "access_token": res.session.access_token,
                "refresh_token": res.session.refresh_token,
                "user": {
                    "id": res.user.id,
                    "email": res.user.email,
                    "full_name": profile.data.get("full_name"),
                    "plan": profile.data.get("plan"),
                    "daily_limit": profile.data.get("daily_limit"),
                    "emails_sent_today": profile.data.get("emails_sent_today", 0)
                }
            }
        raise HTTPException(status_code=401, detail="Invalid credentials")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid email or password")

@app.get("/auth/me")
async def get_me(user=Depends(get_current_user)):
    profile = supabase_admin.table("users").select("*").eq("id", user.id).single().execute()
    return profile.data

# ══════════════════════════════
# DASHBOARD
# ══════════════════════════════

@app.get("/dashboard/stats")
async def get_stats(user=Depends(get_current_user)):
    uid = user.id
    campaigns = supabase_admin.table("campaigns").select("id", count="exact").eq("user_id", uid).execute()
    contacts  = supabase_admin.table("scraped_contacts").select("id", count="exact").eq("user_id", uid).execute()
    sent      = supabase_admin.table("emails_sent").select("id", count="exact").eq("user_id", uid).execute()
    replies   = supabase_admin.table("replies").select("id", count="exact").eq("user_id", uid).execute()
    unread    = supabase_admin.table("replies").select("id", count="exact").eq("user_id", uid).eq("is_read", False).execute()
    return {
        "campaigns": campaigns.count or 0,
        "contacts": contacts.count or 0,
        "emails_sent": sent.count or 0,
        "replies": replies.count or 0,
        "unread_replies": unread.count or 0
    }

# ══════════════════════════════
# SMTP ROUTES
# ══════════════════════════════

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
    # Get SMTP account
    smtp_rec = supabase_admin.table("smtp_accounts").select("*").eq("id", data.smtp_id).eq("user_id", user.id).single().execute()
    if not smtp_rec.data:
        raise HTTPException(status_code=404, detail="SMTP account not found")

    rec = smtp_rec.data
    password = decrypt_password(rec["password_encrypted"])

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = data.subject
        msg["From"] = f"{rec['email']}"
        msg["To"] = data.to_email
        msg.attach(MIMEText("<h2>MailFlow Test Email</h2><p>Your SMTP is working correctly!</p>", "html"))

        context = ssl.create_default_context()
        with smtplib.SMTP(rec["host"], rec["port"], timeout=10) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(rec["email"], password)
            server.sendmail(rec["email"], data.to_email, msg.as_string())

        # Update last tested
        supabase_admin.table("smtp_accounts").update({"last_tested": "now()"}).eq("id", data.smtp_id).execute()
        return {"message": "Test email sent successfully", "status": "ok"}

    except smtplib.SMTPAuthenticationError:
        raise HTTPException(status_code=400, detail="Authentication failed. Check your email and app password.")
    except smtplib.SMTPConnectError:
        raise HTTPException(status_code=400, detail="Could not connect to SMTP server. Check host and port.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"SMTP error: {str(e)}")

@app.delete("/smtp/{smtp_id}")
async def delete_smtp(smtp_id: str, user=Depends(get_current_user)):
    supabase_admin.table("smtp_accounts").delete().eq("id", smtp_id).eq("user_id", user.id).execute()
    return {"message": "SMTP account deleted"}

# ══════════════════════════════
# CONTACTS
# ══════════════════════════════

@app.get("/contacts")
async def get_contacts(user=Depends(get_current_user)):
    result = supabase_admin.table("scraped_contacts").select("*").eq("user_id", user.id).order("created_at", desc=True).execute()
    return result.data

@app.post("/contacts/add")
async def add_contact(contact: dict, user=Depends(get_current_user)):
    contact["user_id"] = user.id
    result = supabase_admin.table("scraped_contacts").insert(contact).execute()
    return result.data[0]

@app.delete("/contacts/{contact_id}")
async def delete_contact(contact_id: str, user=Depends(get_current_user)):
    supabase_admin.table("scraped_contacts").delete().eq("id", contact_id).eq("user_id", user.id).execute()
    return {"message": "Contact deleted"}

# ══════════════════════════════
# SCRAPER
# ══════════════════════════════

@app.post("/scraper/search")
async def scrape_emails(data: ScrapeModel, user=Depends(get_current_user)):
    import httpx
    results = []

    # Apollo.io API
    apollo_key = os.getenv("APOLLO_API_KEY")
    if apollo_key:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                res = await client.post(
                    "https://api.apollo.io/v1/mixed_people/search",
                    headers={"Content-Type": "application/json", "Cache-Control": "no-cache"},
                    json={
                        "api_key": apollo_key,
                        "q_keywords": data.niche,
                        "per_page": data.limit,
                        "page": 1
                    }
                )
                if res.status_code == 200:
                    people = res.json().get("people", [])
                    for p in people:
                        email = p.get("email")
                        if email and "@" in email:
                            results.append({
                                "name": f"{p.get('first_name','')} {p.get('last_name','')}".strip(),
                                "email": email,
                                "company": p.get("organization", {}).get("name", ""),
                                "website": p.get("organization", {}).get("website_url", ""),
                                "source": "apollo"
                            })
        except Exception as e:
            logger.error(f"Apollo error: {e}")

    # Hunter.io API
    hunter_key = os.getenv("HUNTER_API_KEY")
    if hunter_key and len(results) < data.limit:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                res = await client.get(
                    "https://api.hunter.io/v2/domain-search",
                    params={"domain": data.niche.replace(" ", ""), "api_key": hunter_key, "limit": 10}
                )
                if res.status_code == 200:
                    emails = res.json().get("data", {}).get("emails", [])
                    for e in emails:
                        results.append({
                            "name": f"{e.get('first_name','')} {e.get('last_name','')}".strip(),
                            "email": e.get("value"),
                            "company": res.json().get("data", {}).get("organization", ""),
                            "website": "",
                            "source": "hunter"
                        })
        except Exception as e:
            logger.error(f"Hunter error: {e}")

    # Remove duplicates
    seen = set()
    unique = []
    for r in results:
        if r["email"] not in seen:
            seen.add(r["email"])
            unique.append(r)

    return {"results": unique, "count": len(unique), "niche": data.niche}

@app.post("/scraper/save")
async def save_scraped(contacts: List[dict], user=Depends(get_current_user)):
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
            pass  # Skip duplicates
    return {"message": f"{saved} contacts saved", "saved": saved}

# ══════════════════════════════
# CAMPAIGNS
# ══════════════════════════════

@app.post("/campaigns/create")
async def create_campaign(data: CampaignModel, user=Depends(get_current_user)):
    result = supabase_admin.table("campaigns").insert({
        "user_id": user.id,
        "name": data.name,
        "subject": data.subject,
        "template_body": data.template_body,
        "from_name": data.from_name,
        "reply_to": data.reply_to,
        "status": "draft",
        "total_contacts": len(data.contact_ids),
        "sent_count": 0,
        "open_count": 0,
        "reply_count": 0,
        "is_ai_personalized": True
    }).execute()
    return result.data[0]

@app.get("/campaigns")
async def get_campaigns(user=Depends(get_current_user)):
    result = supabase_admin.table("campaigns").select("*").eq("user_id", user.id).order("created_at", desc=True).execute()
    return result.data

@app.post("/campaigns/{campaign_id}/send")
async def send_campaign(campaign_id: str, background_tasks: BackgroundTasks, user=Depends(get_current_user)):
    # Get campaign
    camp = supabase_admin.table("campaigns").select("*").eq("id", campaign_id).eq("user_id", user.id).single().execute()
    if not camp.data:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Get active SMTP
    smtp_list = supabase_admin.table("smtp_accounts").select("*").eq("user_id", user.id).eq("is_active", True).execute()
    if not smtp_list.data:
        raise HTTPException(status_code=400, detail="No active SMTP accounts. Add one first.")

    # Get contacts
    contacts = supabase_admin.table("scraped_contacts").select("*").eq("user_id", user.id).execute()
    if not contacts.data:
        raise HTTPException(status_code=400, detail="No contacts found. Scrape some emails first.")

    # Start sending in background
    background_tasks.add_task(
        send_bulk_emails,
        campaign=camp.data,
        contacts=contacts.data,
        smtp_accounts=smtp_list.data,
        user_id=user.id
    )

    # Update campaign status
    supabase_admin.table("campaigns").update({"status": "sending", "started_at": "now()"}).eq("id", campaign_id).execute()

    return {"message": f"Campaign started. Sending to {len(contacts.data)} contacts.", "status": "sending"}

async def send_bulk_emails(campaign: dict, contacts: list, smtp_accounts: list, user_id: str):
    smtp_idx = 0
    sent_count = 0

    for contact in contacts:
        try:
            # Rotate SMTP if limit hit
            smtp = smtp_accounts[smtp_idx % len(smtp_accounts)]
            if smtp["sent_today"] >= smtp["daily_limit"]:
                smtp_idx += 1
                if smtp_idx >= len(smtp_accounts):
                    logger.info("All SMTP accounts hit daily limit")
                    break
                smtp = smtp_accounts[smtp_idx]

            password = decrypt_password(smtp["password_encrypted"])

            # Personalize email
            body = campaign["template_body"].replace("{{name}}", contact.get("name", "there"))
            body = body.replace("{{company}}", contact.get("company", "your company"))

            msg = MIMEMultipart("alternative")
            msg["Subject"] = campaign["subject"]
            msg["From"] = f"{campaign.get('from_name', '')} <{smtp['email']}>"
            msg["To"] = contact["email"]
            if campaign.get("reply_to"):
                msg["Reply-To"] = campaign["reply_to"]

            # Tracking pixel
            tracking_id = f"{campaign['id']}-{contact['id']}"
            pixel = f'<img src="https://yourapp.railway.app/track/{tracking_id}" width="1" height="1">'
            html_body = f"{body}<br><br>{pixel}"
            msg.attach(MIMEText(html_body, "html"))

            # Unsubscribe footer
            msg.attach(MIMEText(f"{body}\n\nTo unsubscribe reply with UNSUBSCRIBE", "plain"))

            # Send
            context = ssl.create_default_context()
            with smtplib.SMTP(smtp["host"], smtp["port"], timeout=15) as server:
                server.starttls(context=context)
                server.login(smtp["email"], password)
                server.sendmail(smtp["email"], contact["email"], msg.as_string())

            # Log sent email
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

            # Update SMTP sent count
            supabase_admin.table("smtp_accounts").update({"sent_today": smtp["sent_today"] + 1}).eq("id", smtp["id"]).execute()

            sent_count += 1
            logger.info(f"Sent to {contact['email']}")

            # Small delay to avoid spam filters
            import asyncio
            await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"Failed to send to {contact.get('email')}: {e}")

    # Update campaign
    supabase_admin.table("campaigns").update({
        "status": "completed",
        "sent_count": sent_count,
        "completed_at": "now()"
    }).eq("id", campaign["id"]).execute()

    logger.info(f"Campaign {campaign['id']} complete. Sent: {sent_count}")

# ══════════════════════════════
# INBOX
# ══════════════════════════════

@app.get("/inbox/sent")
async def get_sent(user=Depends(get_current_user)):
    result = supabase_admin.table("emails_sent").select("*").eq("user_id", user.id).order("sent_at", desc=True).limit(100).execute()
    return result.data

@app.get("/inbox/replies")
async def get_replies(user=Depends(get_current_user)):
    result = supabase_admin.table("replies").select("*").eq("user_id", user.id).order("received_at", desc=True).execute()
    return result.data

@app.post("/inbox/replies/{reply_id}/read")
async def mark_read(reply_id: str, user=Depends(get_current_user)):
    supabase_admin.table("replies").update({"is_read": True}).eq("id", reply_id).eq("user_id", user.id).execute()
    return {"message": "Marked as read"}

# ══════════════════════════════
# OPEN TRACKING
# ══════════════════════════════

@app.get("/track/{tracking_id}")
async def track_open(tracking_id: str):
    try:
        supabase_admin.table("emails_sent").update({
            "is_opened": True, "opened_at": "now()"
        }).eq("tracking_pixel_id", tracking_id).execute()
    except Exception:
        pass
    # Return 1x1 transparent pixel
    from fastapi.responses import Response
    pixel = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")
    return Response(content=pixel, media_type="image/gif")



@app.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, user=Depends(get_current_user)):
    try:
        # Delete all user data first
        supabase_admin.table("replies").delete().eq("user_id", user_id).execute()
        supabase_admin.table("emails_sent").delete().eq("user_id", user_id).execute()
        supabase_admin.table("campaigns").delete().eq("user_id", user_id).execute()
        supabase_admin.table("scraped_contacts").delete().eq("user_id", user_id).execute()
        supabase_admin.table("smtp_accounts").delete().eq("user_id", user_id).execute()
        supabase_admin.table("users").delete().eq("id", user_id).execute()
        # Delete from Supabase Auth
        supabase_admin.auth.admin.delete_user(user_id)
        return {"message": "User deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    


    # Add these routes to the END of your main.py file
import hmac
import hashlib
import json

# ══════════════════════════════
# PAYSTACK PAYMENT ROUTES
# ══════════════════════════════

PLANS = {
    "personal": {
        "name": "Personal",
        "amount_ngn": 650000,   # ₦6,500 in kobo
        "amount_usd": 400,      # $4 in cents
        "daily_limit": 1500,
        "contacts_limit": 20000,
        "smtp_limit": 3,
        "scraper_limit": 400,
        "campaigns_limit": 10,
        "ai_personalization": True,
        "auto_followup": False
    },
    "corporate": {
        "name": "Corporate",
        "amount_ngn": 2400000,  # ₦24,000 in kobo
        "amount_usd": 1500,     # $15 in cents
        "daily_limit": 5000,
        "contacts_limit": 100000,
        "smtp_limit": 7,
        "scraper_limit": 2000,
        "campaigns_limit": 40,
        "ai_personalization": True,
        "auto_followup": True
    }
}

class InitiatePaymentModel(BaseModel):
    plan: str
    currency: str = "NGN"  # NGN or USD

@app.post("/payments/initiate")
async def initiate_payment(data: InitiatePaymentModel, user=Depends(get_current_user)):
    if data.plan not in PLANS:
        raise HTTPException(status_code=400, detail="Invalid plan. Choose 'personal' or 'corporate'")

    if data.currency not in ["NGN", "USD"]:
        raise HTTPException(status_code=400, detail="Invalid currency. Choose 'NGN' or 'USD'")

    plan = PLANS[data.plan]
    amount = plan["amount_ngn"] if data.currency == "NGN" else plan["amount_usd"]

    secret_key = os.getenv("PAYSTACK_SECRET_KEY")

    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(
                "https://api.paystack.co/transaction/initialize",
                headers={
                    "Authorization": f"Bearer {secret_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "email": user.email,
                    "amount": amount,
                    "currency": data.currency,
                    "metadata": {
                        "user_id": user.id,
                        "plan": data.plan,
                        "currency": data.currency
                    },
                    "callback_url": f"{os.getenv('FRONTEND_URL', 'darling-moonbeam-cca341.netlify.app')}/payment-success"
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


@app.get("/payments/verify/{reference}")
async def verify_payment(reference: str, user=Depends(get_current_user)):
    secret_key = os.getenv("PAYSTACK_SECRET_KEY")

    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(
                f"https://api.paystack.co/transaction/verify/{reference}",
                headers={"Authorization": f"Bearer {secret_key}"}
            )

        result = res.json()

        if result.get("status") and result["data"]["status"] == "success":
            metadata = result["data"].get("metadata", {})
            plan = metadata.get("plan")

            if plan in PLANS:
                plan_data = PLANS[plan]

                # Update user plan in database
                supabase_admin.table("users").update({
                    "plan": plan,
                    "daily_limit": plan_data["daily_limit"],
                    "plan_expires_at": "now() + interval '30 days'"
                }).eq("id", user.id).execute()

                # Log the payment
                supabase_admin.table("payments").insert({
                    "user_id": user.id,
                    "plan": plan,
                    "amount": result["data"]["amount"],
                    "currency": result["data"]["currency"],
                    "reference": reference,
                    "status": "success"
                }).execute()

                return {
                    "message": f"Payment successful! {plan_data['name']} plan activated.",
                    "plan": plan,
                    "daily_limit": plan_data["daily_limit"]
                }

        raise HTTPException(status_code=400, detail="Payment verification failed")

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/payments/webhook")
async def paystack_webhook(request: Request):
    secret_key = os.getenv("PAYSTACK_SECRET_KEY")
    body = await request.body()

    # Verify webhook signature
    signature = request.headers.get("x-paystack-signature", "")
    expected = hmac.new(
        secret_key.encode(),
        body,
        hashlib.sha512
    ).hexdigest()

    if signature != expected:
        raise HTTPException(status_code=400, detail="Invalid signature")

    event = json.loads(body)

    if event.get("event") == "charge.success":
        data = event["data"]
        metadata = data.get("metadata", {})
        user_id = metadata.get("user_id")
        plan = metadata.get("plan")

        if user_id and plan and plan in PLANS:
            plan_data = PLANS[plan]
            supabase_admin.table("users").update({
                "plan": plan,
                "daily_limit": plan_data["daily_limit"],
                "plan_expires_at": "now() + interval '30 days'"
            }).eq("id", user_id).execute()

    return {"status": "ok"}


@app.get("/payments/plans")
async def get_plans():
    return {
        "free": {
            "name": "Free",
            "price_ngn": 0,
            "price_usd": 0,
            "daily_limit": 100,
            "contacts_limit": 500,
            "smtp_limit": 1,
            "scraper_limit": 10,
            "campaigns_limit": 1,
            "ai_personalization": False,
            "auto_followup": False,
            "ads": True
        },
        "personal": {
            "name": "Personal",
            "price_ngn": 6500,
            "price_usd": 4,
            "daily_limit": 1500,
            "contacts_limit": 20000,
            "smtp_limit": 3,
            "scraper_limit": 400,
            "campaigns_limit": 10,
            "ai_personalization": True,
            "auto_followup": False,
            "ads": False
        },
        "corporate": {
            "name": "Corporate",
            "price_ngn": 24000,
            "price_usd": 15,
            "daily_limit": 5000,
            "contacts_limit": 100000,
            "smtp_limit": 7,
            "scraper_limit": 2000,
            "campaigns_limit": 40,
            "ai_personalization": True,
            "auto_followup": True,
            "ads": False
        }
    }
