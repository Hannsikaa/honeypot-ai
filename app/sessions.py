SESSIONS = {}

def get_session(session_id):
    if session_id not in SESSIONS:
        SESSIONS[session_id] = {
            "messages": [],
            "scam_detected": False,
            "extracted": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": []
            }
        }
    return SESSIONS[session_id]

def update_session(session_id, message, history):
    session = get_session(session_id)
    session["messages"].append(message)
    for h in history:
        session["messages"].append(h)
