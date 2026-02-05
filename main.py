from fastapi import FastAPI, Request, Header
from fastapi.responses import JSONResponse
import asyncio
import httpx
import os
import logging
import uuid
import re

# =====================
# APP INIT
# =====================
app = FastAPI()
logging.basicConfig(level=logging.INFO)

# =====================
# CONFIG
# =====================
API_KEY = os.getenv("API_KEY", "honeypot123")
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# =====================
# IN-MEMORY SESSION TRACKING
# =====================
SESSION_STATE = {}
# structure:
# {
#   sessionId: {
#       "callback_sent": bool,
#       "total_messages": int
#   }
# }

# =====================
# SCAM DETECTION
# =====================
SCAM_KEYWORDS = [
    "urgent", "verify", "blocked", "suspend",
    "upi", "bank", "account", "immediately",
    "otp", "link"
]

def is_scam(text: str) -> bool:
    text = text.lower()
    return any(keyword in text for keyword in SCAM_KEYWORDS)

# =====================
# AGENT RESPONSE LOGIC
# =====================
def agent_reply(conversation_history):
    turn = len(conversation_history)

    if turn == 0:
        return "Why is my account being suspended?"

    if turn == 1:
        return "I just want to understand what went wrong with my account."

    if turn == 2:
        return "What details do you need from me to fix this?"

    return "Please explain clearly, I am getting confused."

# =====================
# INTELLIGENCE EXTRACTION
# =====================
def extract_intelligence(text: str):
    return {
        "bankAccounts": re.findall(r"\b\d{4}-\d{4}-\d{4}\b", text),
        "upiIds": re.findall(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b", text),
        "phishingLinks": re.findall(r"https?://\S+", text),
        "phoneNumbers": re.findall(r"\+91\d{10}", text),
        "suspiciousKeywords": [k for k in SCAM_KEYWORDS if k in text.lower()]
    }

# =====================
# GUVI FINAL CALLBACK
# =====================
async def send_final_callback(session_id, total_msgs, intelligence):
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": total_msgs,
        "extractedIntelligence": intelligence,
        "agentNotes": "Scammer used urgency and verification pressure tactics"
    }

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(GUVI_CALLBACK_URL, json=payload)
            logging.info(f"Final callback sent for session {session_id}")
    except Exception as e:
        logging.error(f"GUVI callback failed for session {session_id}: {e}")

# =====================
# BACKGROUND TASK
# =====================
async def background_task(session_id, text, total_msgs):
    intelligence = extract_intelligence(text)
    await send_final_callback(session_id, total_msgs, intelligence)

# =====================
# WEBHOOK ENDPOINT
# =====================
@app.post("/webhook")
async def webhook(request: Request, x_api_key: str = Header(None)):

    # -------- AUTH (SOFT FAIL SAFE) --------
    if x_api_key and x_api_key != API_KEY:
        return JSONResponse(
            status_code=401,
            content={"status": "error", "reply": "Unauthorized"}
        )

    # -------- PARSE BODY --------
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            content={"status": "success", "reply": "Why is my account being suspended?"}
        )

    session_id = body.get("sessionId") or str(uuid.uuid4())
    message = body.get("message", {})
    conversation_history = body.get("conversationHistory", [])

    sender = message.get("sender")
    text = message.get("text", "")

    # -------- INIT SESSION STATE --------
    if session_id not in SESSION_STATE:
        SESSION_STATE[session_id] = {
            "callback_sent": False,
            "total_messages": 0
        }

    SESSION_STATE[session_id]["total_messages"] += 1
    total_msgs = SESSION_STATE[session_id]["total_messages"]

    # -------- ONLY ENGAGE SCAMMER --------
    if sender != "scammer":
        return JSONResponse(
            content={
                "status": "success",
                "reply": "Okay."
            }
        )

    # -------- SCAM DETECTION --------
    if is_scam(text):
        reply = agent_reply(conversation_history)

        # -------- FINAL CALLBACK CONDITIONS --------
        if (
            len(conversation_history) >= 2
            and not SESSION_STATE[session_id]["callback_sent"]
        ):
            SESSION_STATE[session_id]["callback_sent"] = True
            asyncio.create_task(
                background_task(session_id, text, total_msgs)
            )

        return JSONResponse(
            content={
                "status": "success",
                "reply": reply
            }
        )

    # -------- NON-SCAM FALLBACK --------
    return JSONResponse(
        content={
            "status": "success",
            "reply": "Sorry, could you clarify?"
        }
    )

# =====================
# HEALTH CHECK
# =====================
@app.get("/")
async def health():
    return {"status": "alive"}
