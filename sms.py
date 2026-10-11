import os
import re
from dotenv import load_dotenv
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException

load_dotenv()

_client = Client(os.environ["TWILIO_ACCOUNT_SID"], os.environ["TWILIO_AUTH_TOKEN"])
_FROM = os.environ["TWILIO_PHONE_NUMBER"]


def normalize_indian_number(phone: str) -> str | None:
    """Return +91XXXXXXXXXX, or None if the number looks invalid."""
    digits = re.sub(r"\D", "", phone)
    if len(digits) == 10:
        digits = "91" + digits
    if re.fullmatch(r"91[6-9]\d{9}", digits):
        return "+" + digits
    return None


def send_sms(to: str, body: str) -> bool:
    number = normalize_indian_number(to)
    if not number:
        return False
    try:
        _client.messages.create(body=body, from_=_FROM, to=number)
        return True
    except TwilioRestException as e:
        print("SMS failed:", e.msg)
        return False


def send_order_confirmation(phone: str, order_id: str, total: float) -> bool:
    return send_sms(
        phone,
        f"WEARUP: Thank you! Your order #{order_id} (Rs {total:.2f}) is confirmed.",
    )