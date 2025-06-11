from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.hashes
import cryptography.exceptions
from django.conf import settings
import base64
import binascii
import json
import logging
import uuid
from .. import tasks

logger = logging.getLogger(__name__)


def verify_postal_sig(inner):
    @csrf_exempt
    def wrapper(request, *args, **kwargs):
        if request.method != "POST":
            return HttpResponse(status=405)

        orig_sig = request.headers.get("X-Postal-Signature")
        if not orig_sig:
            return HttpResponse(status=400)

        try:
            orig_sig = base64.b64decode(orig_sig)
        except binascii.Error:
            return HttpResponse(status=400)

        pubkey_bytes = base64.b64decode(settings.POSTAL_PUBLIC_KEY)
        pubkey = cryptography.hazmat.primitives.serialization.load_der_public_key(pubkey_bytes)
        try:
            pubkey.verify(
                orig_sig, request.body,
                cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
                cryptography.hazmat.primitives.hashes.SHA1()
            )
        except cryptography.exceptions.InvalidSignature:
            return HttpResponse(status=401)

        try:
            req_body = json.loads(request.body.decode())
        except (json.JSONDecodeError, UnicodeError):
            return HttpResponse(status=400)

        return inner(request, req_body, *args, **kwargs)

    return wrapper


@verify_postal_sig
def postal(_request, req_body):
    msg_to = req_body.get('rcpt_to')
    msg_from = req_body.get('mail_from')
    msg_bytes = req_body.get("message")

    logger.info(f"Got email webhook; from: {msg_from}, to: {msg_to}")

    zone_id = msg_to.split("@")[0]
    try:
        zone_id = uuid.UUID(zone_id)
    except ValueError:
        logger.warning("Invalid UUID recipient")
        return HttpResponse(status=200)

    tasks.forward_soa_email.delay(zone_id, msg_bytes)
    return HttpResponse(status=200)