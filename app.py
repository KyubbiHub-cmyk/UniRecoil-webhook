import os
import json
import hmac
import hashlib
import secrets
from flask import Flask, request, Response
import firebase_admin
from firebase_admin import credentials, firestore

app = Flask(__name__)

SELLAUTH_WEBHOOK_SECRET = os.environ.get("SELLAUTH_WEBHOOK_SECRET", "")
FIREBASE_SERVICE_ACCOUNT_JSON = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON", "")

if not FIREBASE_SERVICE_ACCOUNT_JSON:
    raise RuntimeError("Missing FIREBASE_SERVICE_ACCOUNT_JSON environment variable")

service_account_info = json.loads(FIREBASE_SERVICE_ACCOUNT_JSON)

cred = credentials.Certificate(service_account_info)
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

db = firestore.client()

# Replace these with your real SellAuth variant IDs
VARIANT_DURATION_MAP = {
    1111: {"duration_hours": 24},  # 24 Hours
    2222: {"duration_days": 7},    # 7 Days
    3333: {"duration_days": 30},   # 30 Days
}


def generate_numeric_key(length=24):
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def generate_unique_key(length=24, max_attempts=100):
    for _ in range(max_attempts):
        key = generate_numeric_key(length)
        if not db.collection("Script").document(key).get().exists:
            return key
    raise RuntimeError("Could not generate unique key")


def verify_signature(raw_body, signature):
    expected = hmac.new(
        SELLAUTH_WEBHOOK_SECRET.encode(),
        raw_body,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature or "")


@app.get("/")
def home():
    return "UniRecoil SellAuth webhook online", 200


@app.post("/sellauth/delivery")
def sellauth_delivery():
    raw_body = request.get_data()
    signature = request.headers.get("X-Signature")

    if not verify_signature(raw_body, signature):
        return Response("Invalid signature", status=401)

    payload = request.get_json(force=True)

    if payload.get("event") != "INVOICE.ITEM.DELIVER-DYNAMIC":
        return Response("Ignored", status=200)

    item = payload["item"]
    customer = payload.get("customer", {})
    invoice_id = payload["id"]
    item_id = str(item["id"])
    variant = item.get("variant") or {}
    variant_id = variant.get("id")

    if variant_id not in VARIANT_DURATION_MAP:
        return Response("Unknown variant", status=400)

    # Prevent duplicate key creation if SellAuth retries
    delivery_ref = db.collection("deliveries").document(item_id)
    existing = delivery_ref.get()
    if existing.exists:
        existing_key = existing.to_dict()["key"]
        return Response(existing_key, status=200, mimetype="text/plain")

    key = generate_unique_key()
    duration_data = VARIANT_DURATION_MAP[variant_id]

    db.collection("Script").document(key).set({
        "valid": True,
        "used": False,
        **duration_data,
        "email": customer.get("email"),
        "invoice_id": invoice_id,
        "invoice_item_id": item["id"],
        "variant_id": variant_id,
        "source": "sellauth",
    })

    delivery_ref.set({
        "key": key,
        "invoice_id": invoice_id,
        "invoice_item_id": item["id"],
    })

    return Response(key, status=200, mimetype="text/plain")
