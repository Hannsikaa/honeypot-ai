from fastapi import FastAPI, Header, HTTPException
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
# DATA MODELS
# -------------------------------------------------

class Message(BaseModel):
    sender: str
    text: str
    timestamp: str

class WebhookRequest(BaseModel):
    sessionId: Optional[str] = None
    message: Optional[Message] = None
    conversationHistory: List[Dict] = []
    metadata: Dict = {}

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
    return not any([
        intel["upi_ids"],
        intel["phone_numbers"],
        intel["links"],
        intel["keywords"]
    ])

def violates_safety(reply: str) -> bool:
    r = reply.lower()
    return any(p in r for p in FORBIDDEN_REPLY_PATTERNS)

# -------------------------------------------------
# RISK SCORING
# -------------------------------------------------

def count_payment_pressure(conversation_history: List[Dict]) -> int:
    payment_words = ["pay", "payment", "send", "transfer", "amount"]
    count = 0
    for msg in conversation_history:
        if msg.get("sender") == "scammer":
            if any(w in msg.get("text", "").lower() for w in payment_words):
                count += 1
    return count

def calculate_risk(intel: Dict, message_text: str, conversation_history: List[Dict]) -> int:
    risk_score = 0
    text_lower = message_text.lower()

    if intel["keywords"]:
        risk_score += 30
    if intel["links"]:
        risk_score += 20
    if intel["phone_numbers"]:
        risk_score += 20
    if intel["upi_ids"]:
        risk_score += 30

    previous_threat = any(
        any(k in h.get("text", "").lower() for k in ["blocked", "suspended", "account", "kyc"])
        for h in conversation_history
    )

    current_payment = any(k in text_lower for k in ["pay", "payment", "send", "transfer"])

    if previous_threat and current_payment:
        risk_score += 15

    if any(p in text_lower for p in URGENCY_PHRASES):
        risk_score += 10

    pressure = count_payment_pressure(conversation_history)
    if pressure >= 4:
        risk_score += 15
    elif pressure == 3:
        risk_score += 10
    elif pressure == 2:
        risk_score += 5

    agent_confused = any(
        h.get("sender") == "agent" and
        any(w in h.get("text", "").lower() for w in ["samajh", "clear", "understand", "confuse"])
        for h in conversation_history
    )

    if agent_confused and current_payment:
        risk_score += 10

    return min(risk_score, 80)

def smooth_confidence(raw_confidence: float, conversation_history: List[Dict]) -> float:
    baseline = min(0.15 + (len(conversation_history) * 0.05), 0.6)
    smoothed = min(raw_confidence, baseline)
    return round(min(max(smoothed, 0.05), 0.95), 2)

def classify_threat_level(risk_score: int, scam_confidence: float) -> str:
    if risk_score >= 80 or scam_confidence >= 0.8:
        return "critical"
    if risk_score >= 60 or scam_confidence >= 0.6:
        return "high"
    if risk_score >= 30 or scam_confidence >= 0.3:
        return "medium"
    return "low"

# -------------------------------------------------
# FALLBACK REPLIES
# -------------------------------------------------

FALLBACK_REPLIES = {
    "keywords": [
        "yeh thoda serious lag raha hai, account mein kya problem hai?",
        "main thodi confuse ho gayi hoon, please clearly bata do",
        "samajh nahi aa raha, thoda detail mein explain kar sakte ho?"
    ],
    "phone": [
        "call abhi mushkil hai, pehle thoda samjha do kya karna hai",
        "number mil gaya, lekin mujhe thoda dar lag raha hai"
    ],
    "link": [
        "link open karne se pehle confirm karna tha, usmein kya hoga?",
        "yeh link safe hai na? bas pooch rahi hoon"
    ],
    "generic": [
        "please thoda clearly samjha do",
        "main process samajhne ki koshish kar rahi hoon"
    ]
}

# -------------------------------------------------
# GEMINI REPLY
# -------------------------------------------------

def ai_victim_reply(message_text: str, intel: Dict) -> str:
    intent = "general confusion"

    if intel["upi_ids"]:
        intent = "upi mention"
    elif intel["phone_numbers"]:
        intent = "call request"
    elif intel["links"]:
        intent = "link sent"
    elif intel["keywords"]:
        intent = "urgent or threatening"

    prompt = f"""
Incoming scam message:
"{message_text}"

Context:
{intent}

Write ONE short Hinglish reply.
Human, worried, cooperative.
No repetition.
"""

    try:
        reply = model.generate_content(prompt).text.strip()
    except Exception:
        reply = None

    if not reply or violates_safety(reply):
        if intel["phone_numbers"]:
            return random.choice(FALLBACK_REPLIES["phone"])
        if intel["links"]:
            return random.choice(FALLBACK_REPLIES["link"])
        if intel["keywords"]:
            return random.choice(FALLBACK_REPLIES["keywords"])
        return random.choice(FALLBACK_REPLIES["generic"])

    return reply

# -------------------------------------------------
# WEBHOOK (ONLY FIX IS HERE)
# -------------------------------------------------

@app.post("/webhook", response_model=WebhookResponse)
def webhook(
    payload: Dict[str, Any],
    x_api_key: str = Header(..., alias="x-api-key")  # ✅ REQUIRED FIX
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    text = (
        payload.get("message", {}).get("text")
        or payload.get("text")
        or ""
    ).strip()

    if not text:
        return WebhookResponse(
            status="ignored",
            reply=None,
            risk_score=0,
            scam_confidence=0.05,
            intel=None
        )

    conversation_history = payload.get("conversationHistory", [])
    intel = extract_intel(text)

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
            "turn_count": len(conversation_history) + 1,
            "engagement_active": True
        }
    )

@app.get("/")
def root():
    return {"status": "ok"}
