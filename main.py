from fastapi import FastAPI, Header, HTTPException, Body
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import re
import os
import random

# ✅ CORRECT GEMINI IMPORT (DO NOT CHANGE)
import google.generativeai as genai

# -------------------------------------------------
# CONFIG
# -------------------------------------------------

app = FastAPI(title="Scam Honeypot API", version="1.0.0")

API_KEY = "honeypot123"

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
- Never ask for UPI
- Act confused, worried, cooperative
- Let scammer feel in control
- Ask for clarification
- Do not repeat sentences
"""
)

# -------------------------------------------------
# RESPONSE MODEL (KEEP STRICT)
# -------------------------------------------------

class WebhookResponse(BaseModel):
    status: str
    reply: Optional[str]
    risk_score: int
    scam_confidence: float
    intel: Optional[Dict]

# -------------------------------------------------
# REGEX & KEYWORDS
# -------------------------------------------------

UPI_REGEX = r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b"
PHONE_REGEX = r"\b[6-9]\d{9}\b"
LINK_REGEX = r"https?://[^\s]+"

KEYWORDS = [
    "urgent", "blocked", "verify", "bank", "account",
    "suspended", "limited", "immediately", "pay", "payment"
]

URGENCY_PHRASES = ["quickly", "urgent", "immediately", "asap", "right now"]

FORBIDDEN_REPLY_PATTERNS = [
    "send money",
    "pay now",
    "upi id",
    "payment link",
    "i will pay",
    "already paid",
    "paise bhej"
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

def is_clean_message(intel: Dict) -> bool:
    return not any(intel.values())

def violates_safety(reply: str) -> bool:
    r = reply.lower()
    return any(p in r for p in FORBIDDEN_REPLY_PATTERNS)

# -------------------------------------------------
# RISK SCORING
# -------------------------------------------------

def count_payment_pressure(conversation_history: List[Dict]) -> int:
    payment_words = ["pay", "payment", "send", "transfer", "amount"]
    return sum(
        1 for h in conversation_history
        if any(w in h.get("text", "").lower() for w in payment_words)
    )

def calculate_risk(intel: Dict, text: str, history: List[Dict]) -> int:
    score = 0

    if intel["keywords"]:
        score += 30
    if intel["links"]:
        score += 20
    if intel["phone_numbers"]:
        score += 20
    if intel["upi_ids"]:
        score += 30

    if any(p in text.lower() for p in URGENCY_PHRASES):
        score += 10

    pressure = count_payment_pressure(history)
    score += min(pressure * 5, 15)

    return min(score, 80)

def smooth_confidence(raw: float, history: List[Dict]) -> float:
    baseline = min(0.15 + len(history) * 0.05, 0.6)
    return round(min(max(min(raw, baseline), 0.05), 0.95), 2)

def classify_threat_level(score: int, confidence: float) -> str:
    if score >= 80 or confidence >= 0.8:
        return "critical"
    if score >= 60 or confidence >= 0.6:
        return "high"
    if score >= 30 or confidence >= 0.3:
        return "medium"
    return "low"

# -------------------------------------------------
# FALLBACKS
# -------------------------------------------------

FALLBACK_REPLIES = {
    "generic": [
        "samajh nahi aa raha, thoda clearly bata sakte ho?",
        "main thodi confuse ho gayi hoon, please explain karo",
        "yeh thoda serious lag raha hai, detail mein batao"
    ]
}

# -------------------------------------------------
# GEMINI REPLY
# -------------------------------------------------

def ai_victim_reply(text: str, intel: Dict) -> str:
    prompt = f"""
Incoming scam message:
"{text}"

Write ONE short Hinglish reply.
Human, worried, cooperative.
No repetition.
"""
    try:
        reply = model.generate_content(prompt).text.strip()
        if not violates_safety(reply):
            return reply
    except Exception:
        pass

    return random.choice(FALLBACK_REPLIES["generic"])

# -------------------------------------------------
# WEBHOOK (LOOSE INPUT, STRICT OUTPUT)
# -------------------------------------------------

@app.post("/webhook", response_model=WebhookResponse)
def webhook(
    payload: Dict[str, Any] = Body(...),
    x_api_key: str = Header(...)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # 🔹 Extract text safely from ANY payload shape
    text = (
        payload.get("message", {}).get("text")
        or payload.get("text")
        or payload.get("message")
        or ""
    ).strip()

    conversation_history = payload.get("conversationHistory", [])

    if not text:
        return WebhookResponse(
            status="ignored",
            reply=None,
            risk_score=0,
            scam_confidence=0.05,
            intel=None
        )

    intel = extract_intel(text)

    if is_clean_message(intel):
        return WebhookResponse(
            status="ignored",
            reply=None,
            risk_score=0,
            scam_confidence=0.05,
            intel=None
        )

    risk_score = calculate_risk(intel, text, conversation_history)
    raw_confidence = round(risk_score / 100, 2)
    scam_confidence = smooth_confidence(raw_confidence, conversation_history)
    threat_level = classify_threat_level(risk_score, scam_confidence)

    reply = ai_victim_reply(text, intel)

    return WebhookResponse(
        status="scam_detected",
        reply=reply,
        risk_score=risk_score,
        scam_confidence=scam_confidence,
        intel={
            **intel,
            "risk_score": risk_score,
            "scam_confidence": scam_confidence,
            "threat_level": threat_level,
            "engagement_active": True
        }
    )

@app.get("/")
def root():
    return {"status": "ok"}
