from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import os, smtplib, ssl, logging, hmac, hashlib, json, base64, httpx
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from supabase import create_client, Client
from cryptography.fernet import Fernet

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="MailFlow API", version="2.0.0")

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

class InitiatePaymentModel(BaseModel):
    plan: str
    currency: str = "NGN"

PLANS = {
    "personal": {
        "name": "Personal",
        "amount_ngn": 650000,
        "amount_usd": 400,
        "daily_limit": 1200,
        "contacts_limit": 20000,
        "smtp_limit": 3,
        "scraper_limit": 400,
        "campaigns_limit": 25,
        "ai_personalization": True,
        "auto_followup": False
    },
    "corporate": {
        "name": "Corporate",
        "amount_ngn": 2400000,
        "amount_usd": 1500,
        "daily_limit": 4500,
        "contacts_limit": 100000,
        "smtp_limit": 10,
        "scraper_limit": 2000,
        "campaigns_limit": 55,
        "ai_personalization": True,
        "auto_followup": True
    }
}

@app.get("/")
def root():
    return {"message": "MailFlow API v2.0 running", "status": "ok"}

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
            return {"message": "Account created. Check your email to verify.", "user_id": res.user.id}
        raise HTTPException(status_code=400, detail="Registration failed")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

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

@app.get("/dashboard/stats")
async def get_stats(user=Depends(get_current_user)):
    uid = user.id
    try:
        campaigns = supabase_admin.table("campaigns").select("id", count="exact").eq("user_id", uid).execute()
        contacts = supabase_admin.table("scraped_contacts").select("id", count="exact").eq("user_id", uid).execute()
        sent = supabase_admin.table("emails_sent").select("id", count="exact").eq("user_id", uid).execute()
        replies = supabase_admin.table("replies").select("id", count="exact").eq("user_id", uid).execute()
        unread = supabase_admin.table("replies").select("id", count="exact").eq("user_id", uid).eq("is_read", False).execute()
        return {
            "campaigns": campaigns.count or 0,
            "contacts": contacts.count or 0,
            "emails_sent": sent.count or 0,
            "replies": replies.count or 0,
            "unread_replies": unread.count or 0
        }
    except Exception:
        return {"campaigns": 0, "contacts": 0, "emails_sent": 0, "replies": 0, "unread_replies": 0}

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
        html = "<h2 style='color:#00d4aa'>MailFlow Test Email</h2><p>Your SMTP is configured correctly!</p>"
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

@app.delete("/contacts/{contact_id}")
async def delete_contact(contact_id: str, user=Depends(get_current_user)):
    supabase_admin.table("scraped_contacts").delete().eq("id", contact_id).eq("user_id", user.id).execute()
    return {"message": "Contact deleted"}

@app.post("/scraper/search")
async def scrape_emails(data: ScrapeModel, user=Depends(get_current_user)):
    results = []
    apollo_key = os.getenv("APOLLO_API_KEY")
    if apollo_key:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                res = await client.post(
                    "https://api.apollo.io/v1/mixed_people/search",
                    headers={"Content-Type": "application/json"},
                    json={"api_key": apollo_key, "q_keywords": data.niche, "per_page": data.limit, "page": 1}
                )
                if res.status_code == 200:
                    for p in res.json().get("people", []):
                        email = p.get("email")
                        if email and "@" in email:
                            results.append({
                                "name": (p.get("first_name", "") + " " + p.get("last_name", "")).strip(),
                                "email": email,
                                "company": p.get("organization", {}).get("name", ""),
                                "website": p.get("organization", {}).get("website_url", ""),
                                "source": "apollo"
                            })
        except Exception as e:
            logger.error("Apollo error: " + str(e))

    hunter_key = os.getenv("HUNTER_API_KEY")
    if hunter_key and len(results) < data.limit:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                res = await client.get(
                    "https://api.hunter.io/v2/domain-search",
                    params={"domain": data.niche.replace(" ", ""), "api_key": hunter_key, "limit": 10}
                )
                if res.status_code == 200:
                    rjson = res.json()
                    for e in rjson.get("data", {}).get("emails", []):
                        results.append({
                            "name": (e.get("first_name", "") + " " + e.get("last_name", "")).strip(),
                            "email": e.get("value"),
                            "company": rjson.get("data", {}).get("organization", ""),
                            "website": "",
                            "source": "hunter"
                        })
        except Exception as e:
            logger.error("Hunter error: " + str(e))

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
    contacts = supabase_admin.table("scraped_contacts").select("*").eq("user_id", user.id).execute()
    if not contacts.data:
        raise HTTPException(status_code=400, detail="No contacts found. Use Email Scraper first.")
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

@app.get("/inbox/replies")
async def get_replies(user=Depends(get_current_user)):
    result = supabase_admin.table("replies").select("*").eq("user_id", user.id).order("received_at", desc=True).execute()
    return result.data

@app.post("/inbox/replies/{reply_id}/read")
async def mark_read(reply_id: str, user=Depends(get_current_user)):
    supabase_admin.table("replies").update({"is_read": True}).eq("id", reply_id).eq("user_id", user.id).execute()
    return {"message": "Marked as read"}

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

@app.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, user=Depends(get_current_user)):
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

@app.get("/payments/plans")
async def get_plans():
    return {
        "free": {"name": "Free", "price_ngn": 0, "price_usd": 0, "daily_limit": 100, "contacts_limit": 500, "smtp_limit": 1, "scraper_limit": 10, "campaigns_limit": 5, "ai_personalization": False, "auto_followup": False, "ads": True},
        "personal": {"name": "Personal", "price_ngn": 6500, "price_usd": 4, "daily_limit": 1200, "contacts_limit": 20000, "smtp_limit": 3, "scraper_limit": 400, "campaigns_limit": 25, "ai_personalization": True, "auto_followup": False, "ads": False},
        "corporate": {"name": "Corporate", "price_ngn": 24000, "price_usd": 15, "daily_limit": 4500, "contacts_limit": 100000, "smtp_limit": 10, "scraper_limit": 2000, "campaigns_limit": 55, "ai_personalization": True, "auto_followup": True, "ads": False}
    }

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
            plan = metadata.get("plan")
            if plan in PLANS:
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
                try:
                    supabase_admin.table("payments").insert({
                        "user_id": user.id,
                        "plan": plan,
                        "amount": result["data"]["amount"],
                        "currency": result["data"]["currency"],
                        "reference": reference,
                        "status": "success"
                    }).execute()
                except Exception:
                    pass
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
            plan = metadata.get("plan")
            if user_id and plan and plan in PLANS:
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

class GmailAccountLabel(BaseModel):
    label: str = "Gmail"
    daily_limit: int = 500

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
            existing = supabase_admin.table("gmail_accounts").select("id").eq(
                "user_id", user_id
            ).eq("gmail_address", gmail_address).execute()

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
                    "daily_limit": 500,
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
        "id, gmail_address, display_name, is_active, sent_today, daily_limit, last_used_at, created_at"
    ).eq("user_id", user.id).execute()
    return result.data

# ── Step 4: Delete Gmail account ──
@app.delete("/gmail/accounts/{account_id}")
async def delete_gmail_account(account_id: str, user=Depends(get_current_user)):
    supabase_admin.table("gmail_accounts").delete().eq(
        "id", account_id
    ).eq("user_id", user.id).execute()
    return {"message": "Gmail account disconnected"}

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
async def send_via_gmail_api(
    account: dict,
    to_email: str,
    subject: str,
    html_body: str,
    plain_body: str,
    from_name: str = None,
    reply_to: str = None
) -> bool:
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

    import httpx
    async with httpx.AsyncClient() as client:
        res = await client.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers={
                "Authorization": "Bearer " + access_token,
                "Content-Type": "application/json",
            },
            json={"raw": raw}
        )

    if res.status_code not in [200, 202]:
        raise Exception("Gmail API error: " + res.text)

    # Update sent count
    supabase_admin.table("gmail_accounts").update({
        "sent_today": account["sent_today"] + 1,
        "last_used_at": datetime.utcnow().isoformat(),
    }).eq("id", account["id"]).execute()

    return True

# ── Step 5: Send test email via Gmail API ──
class GmailTestModel(BaseModel):
    account_id: str
    to_email: str
    subject: str = "Test Email from MailFlow"

# ── Send single custom email via Gmail API (used by Quick Send) ──
class GmailSendModel(BaseModel):
    account_id: str
    to_email: str
    subject: str
    body: str
    from_name: str = None

@app.post("/gmail/send")
async def gmail_send(data: GmailSendModel, user=Depends(get_current_user)):
    account_rec = supabase_admin.table("gmail_accounts").select("*").eq(
        "id", data.account_id
    ).eq("user_id", user.id).single().execute()

    if not account_rec.data:
        raise HTTPException(status_code=404, detail="Gmail account not found")

    account = account_rec.data
    html_body = data.body.replace("\n", "<br>")

    try:
        await send_via_gmail_api(
            account=account,
            to_email=data.to_email,
            subject=data.subject,
            html_body=html_body,
            plain_body=data.body,
            from_name=data.from_name,
        )
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
            html_body="<h2 style='color:#00d4aa'>MailFlow Test Email</h2><p>Your Gmail is connected and working!</p>",
            plain_body="MailFlow Test Email - Your Gmail is connected and working!",
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

    contacts = supabase_admin.table("scraped_contacts").select("*").eq(
        "user_id", user.id
    ).execute()
    if not contacts.data:
        raise HTTPException(
            status_code=400,
            detail="No contacts found. Use Email Scraper first."
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

            await send_via_gmail_api(
                account=account,
                to_email=contact["email"],
                subject=campaign["subject"],
                html_body=html_body,
                plain_body=plain_body,
                from_name=campaign.get("from_name"),
                reply_to=campaign.get("reply_to"),
            )

            # Log sent email
            supabase_admin.table("emails_sent").insert({
                "user_id": user_id,
                "campaign_id": campaign["id"],
                "to_email": contact["email"],
                "to_name": contact.get("name"),
                "subject": campaign["subject"],
                "status": "sent",
                "tracking_pixel_id": tracking_id
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
