# main.py — FINAL BULLETPROOF AGENTIC HONEYPOT (Hackathon Safe)

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import google.generativeai as genai
import os, re, random, json
from typing import Dict, List, Any, Optional

# -------------------------------------------------
# APP CONFIG
# -------------------------------------------------

app = FastAPI(title="Scam Honeypot API", version="1.0.0")

API_KEY = os.getenv("HONEYPOT_API_KEY", "honeypot123")
GEMINI_API_KEY = os.getenv(
    "GEMINI_API_KEY",
    "AIzaSyDLF4JeHMTxU5gEpz5KoL9KbwFWPtotNM8"
)

genai.configure(api_key=GEMINI_API_KEY)

model = genai.GenerativeModel(
    model_name="gemini-1.5-flash",
    system_instruction="""
You are an innocent Indian person replying to scam messages.
Write in Hinglish using English letters.

Rules:
- Never promise to send money
- Never say money is already sent
- Never ask for UPI first
- Act confused, worried, cooperative
- Let scammer feel in control
- Ask for clarification
- Do not repeat sentences
"""
)

# -------------------------------------------------
# REGEX & KEYWORDS
# -------------------------------------------------

UPI_REGEX = r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b"
PHONE_REGEX = r"\b[6-9]\d{9}\b"
LINK_REGEX = r"https?://[^\s]+"

KEYWORDS = [
    "urgent", "blocked", "verify", "bank", "account",
    "suspended", "limited", "immediately", "pay", "payment", "otp"
]

URGENCY_PHRASES = ["quickly", "urgent", "immediately", "asap", "right now"]

FORBIDDEN_REPLY_PATTERNS = [
    "send money", "pay now", "upi id", "payment link",
    "i will pay", "already paid", "paise bhej"
]

# -------------------------------------------------
# UTILITIES
# -------------------------------------------------

def extract_intel(text: str) -> Dict:
    lower = text.lower()
    return {
        "upi_ids": re.findall(UPI_REGEX, text),
        "phone_numbers": re.findall(PHONE_REGEX, text),
        "links": re.findall(LINK_REGEX, text),
        "keywords": [k for k in KEYWORDS if k in lower]
    }

def violates_safety(reply: str) -> bool:
    r = reply.lower()
    return any(p in r for p in FORBIDDEN_REPLY_PATTERNS)

def extract_text(payload: Any) -> str:
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, bytes):
        return payload.decode(errors="ignore")
    if isinstance(payload, dict):
        msg = payload.get("message")
        if isinstance(msg, dict):
            return msg.get("text", "")
        if isinstance(msg, str):
            return msg
        return payload.get("text", "")
    return ""

def extract_history(payload: Any) -> List[Dict]:
    if isinstance(payload, dict):
        h = payload.get("conversationHistory")
        if isinstance(h, list):
            return [x for x in h if isinstance(x, dict)]
    return []

# -------------------------------------------------
# RISK SCORING
# -------------------------------------------------

def count_payment_pressure(history: List[Dict]) -> int:
    words = ["pay", "payment", "send", "transfer", "amount"]
    count = 0
    for m in history:
        if m.get("sender") == "scammer":
            if any(w in m.get("text", "").lower() for w in words):
                count += 1
    return count

def calculate_risk(intel: Dict, text: str, history: List[Dict]) -> int:
    risk = 0
    t = text.lower()

    if intel["keywords"]:
        risk += 30
    if intel["links"]:
        risk += 20
    if intel["phone_numbers"]:
        risk += 20
    if intel["upi_ids"]:
        risk += 30
    if any(p in t for p in URGENCY_PHRASES):
        risk += 10

    pressure = count_payment_pressure(history)
    risk += min(pressure * 5, 15)

    return min(risk, 100)

def classify_threat(risk: int, confidence: float) -> str:
    if risk >= 80 or confidence >= 0.8:
        return "critical"
    if risk >= 60:
        return "high"
    if risk >= 30:
        return "medium"
    return "low"

# -------------------------------------------------
# FALLBACK REPLIES
# -------------------------------------------------

FALLBACK_REPLIES = {
    "upi": [
        "upi ka naam aa raha hai, mujhe thoda doubt ho raha hai",
        "yeh upi wala part clear nahi hai, thoda samjha sakte ho?"
    ],
    "phone": [
        "call abhi possible nahi hai, message mein hi bata do",
        "number mil gaya but mujhe thoda confusion ho raha hai"
    ],
    "link": [
        "link open karne se pehle confirm karna tha, yeh official hai?",
        "yeh link kis website ka hai?"
    ],
    "generic": [
        "mujhe thoda clearly samjha do please",
        "samajh nahi aa raha, kya step follow karna hai?"
    ]
}

# -------------------------------------------------
# GEMINI REPLY
# -------------------------------------------------

def ai_victim_reply(text: str, intel: Dict) -> str:
    prompt = f"""
Incoming message:
"{text}"

Write ONE short Hinglish reply.
Confused, worried, cooperative.
Do not ask for UPI.
"""

    try:
        res = model.generate_content(prompt)
        reply = res.text.strip()
    except Exception:
        reply = None

    if not reply or violates_safety(reply):
        if intel["upi_ids"]:
            return random.choice(FALLBACK_REPLIES["upi"])
        if intel["phone_numbers"]:
            return random.choice(FALLBACK_REPLIES["phone"])
        if intel["links"]:
            return random.choice(FALLBACK_REPLIES["link"])
        return random.choice(FALLBACK_REPLIES["generic"])

    return reply

# -------------------------------------------------
# FINAL BULLETPROOF WEBHOOK
# -------------------------------------------------

@app.post("/webhook")
async def webhook(request: Request):
    headers = request.headers

    api_key = (
        headers.get("x-api-key")
        or headers.get("X-API-KEY")
        or headers.get("authorization")
        or ""
    ).replace("Bearer", "").strip()

    if api_key != API_KEY:
        return JSONResponse(status_code=200, content={"status": "ignored"})

    try:
        body_bytes = await request.body()
        body_str = body_bytes.decode(errors="ignore")
        try:
            payload = json.loads(body_str)
        except Exception:
            payload = body_str
    except Exception:
        payload = {}

    text = extract_text(payload).strip()
    history = extract_history(payload)

    if not text:
        return JSONResponse(
            status_code=200,
            content={
                "status": "ignored",
                "reply": None,
                "risk_score": 0,
                "scam_confidence": 0.05,
                "intel": None
            }
        )

    intel = extract_intel(text)
    risk = calculate_risk(intel, text, history)
    confidence = round(risk / 100, 2)
    threat = classify_threat(risk, confidence)
    reply = ai_victim_reply(text, intel)

    return JSONResponse(
        status_code=200,
        content={
            "status": "scam_detected",
            "reply": reply,
            "risk_score": risk,
            "scam_confidence": confidence,
            "intel": {
                **intel,
                "threat_level": threat,
                "turn_count": len(history) + 1,
                "engagement_active": True
            }
        }
    )

@app.get("/")
def root():
    return {"status": "ok"}
