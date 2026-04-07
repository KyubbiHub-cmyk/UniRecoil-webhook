import os
import json
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import boto3
from flask import Flask, request, Response, jsonify, send_file
import firebase_admin
from firebase_admin import credentials, firestore

app = Flask(__name__)

SELLAUTH_WEBHOOK_SECRET = os.environ.get("SELLAUTH_WEBHOOK_SECRET", "")
FIREBASE_SERVICE_ACCOUNT_JSON = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON", "")

R2_ACCESS_KEY_ID = os.environ.get("R2_ACCESS_KEY_ID", "")
R2_SECRET_ACCESS_KEY = os.environ.get("R2_SECRET_ACCESS_KEY", "")
R2_BUCKET_NAME = os.environ.get("R2_BUCKET_NAME", "")
R2_ENDPOINT_URL = os.environ.get("R2_ENDPOINT_URL", "")
R2_OBJECT_KEY = "UniRecoil.exe"

if not FIREBASE_SERVICE_ACCOUNT_JSON:
    raise RuntimeError("Missing FIREBASE_SERVICE_ACCOUNT_JSON environment variable")

service_account_info = json.loads(FIREBASE_SERVICE_ACCOUNT_JSON)

cred = credentials.Certificate(service_account_info)
if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

db = firestore.client()

s3 = boto3.client(
    "s3",
    endpoint_url=R2_ENDPOINT_URL,
    aws_access_key_id=R2_ACCESS_KEY_ID,
    aws_secret_access_key=R2_SECRET_ACCESS_KEY,
    region_name="auto",
)

VARIANT_DURATION_MAP = {
    1064675: {"duration_hours": 24},
    1072863: {"duration_days": 7},
    1072864: {"duration_days": 30},
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


def get_expiry_from_doc(doc, data):
    created_at = doc.create_time
    if created_at is None:
        return None

    expires_at = data.get("expires_at")
    if expires_at is not None:
        return expires_at

    duration_hours = data.get("duration_hours")
    duration_days = data.get("duration_days")

    if duration_hours is not None:
        return created_at + timedelta(hours=float(duration_hours))
    if duration_days is not None:
        return created_at + timedelta(days=float(duration_days))

    return created_at + timedelta(hours=24)


def validate_key_value(key):
    key = (key or "").strip()
    if not key:
        return False, "Missing key", None

    doc_ref = db.collection("Script").document(key)
    doc = doc_ref.get()

    if not doc.exists:
        return False, "Invalid key", None

    data = doc.to_dict()

    if data.get("valid") is not True:
        return False, "Invalid key", None

    expires_at = get_expiry_from_doc(doc, data)
    if expires_at is None:
        return False, "Key has no expiry", None

    now = datetime.now(timezone.utc)
    if now > expires_at:
        doc_ref.delete()
        return False, "Key expired", None

    return True, "Valid key", {
        "expires_at": expires_at.isoformat(),
        "used": bool(data.get("used", False)),
        "duration_hours": data.get("duration_hours"),
        "duration_days": data.get("duration_days"),
    }


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


@app.post("/launcher/validate")
def launcher_validate():
    payload = request.get_json(force=True, silent=True) or {}
    key = payload.get("key")

    is_valid, message, meta = validate_key_value(key)

    if not is_valid:
        return jsonify({
            "ok": False,
            "message": message,
        }), 400

    return jsonify({
        "ok": True,
        "message": message,
        "meta": meta,
    }), 200


@app.post("/launcher/download")
def launcher_download():
    payload = request.get_json(force=True, silent=True) or {}
    key = payload.get("key")

    is_valid, message, _ = validate_key_value(key)
    if not is_valid:
        return jsonify({
            "ok": False,
            "message": message,
        }), 400

    try:
        signed_url = s3.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": R2_BUCKET_NAME,
                "Key": R2_OBJECT_KEY,
            },
            ExpiresIn=300,
        )
    except Exception as e:
        return jsonify({
            "ok": False,
            "message": f"Could not create download URL: {e}",
        }), 500

    return jsonify({
        "ok": True,
        "url": signed_url,
    }), 200
