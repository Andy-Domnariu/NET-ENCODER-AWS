from django.http import JsonResponse
from django.conf import settings
from src.lib.utils.logger import Logger
from src.lib.utils.utils import Utils
import json

log = Logger("decorator")

# Mapping of path prefixes to specific expected encrypted keys
API_KEY_MAP = {
    "/card/": "NET_ENCODER_API_KEY",
    "/revalidate": "NET_ENCODER_API_KEY",
    "/device/": "NET_ENCODER_API_KEY",
}

def api_key_required(view_func):
    """
    Decorator to protect endpoints with API Key.
    API Key can be passed as:
    - GET / POST param: permission / APIKEY / token
    - Header: X-API-KEY
    - Optionally, caller identity via 'X-CALLER' header (e.g., 'colleague')
    """

    def _wrapped_view(request, *args, **kwargs):
        encrypted_key = (
            request.GET.get("permission")
            or request.GET.get("APIKEY")
            or request.GET.get("token")
            or request.POST.get("permission")
            or request.POST.get("APIKEY")
            or request.POST.get("token")
            or request.headers.get("X-API-KEY")
            or request.META.get("HTTP_X_API_KEY")
            or request.headers.get("x-api-key")
        )
        print(encrypted_key)
        print(request.headers)
        
        if not encrypted_key:
            return JsonResponse({"success": False, "error": "Missing API key."}, status=401)

        incoming_key = encrypted_key.strip()
        print(incoming_key)
        path = request.path
        expected_key_setting = None

        # Find which key should be used based on the path
        for prefix, setting_key in API_KEY_MAP.items():
            if path.startswith(prefix):
                expected_key_setting = setting_key
                break

        if not expected_key_setting:
            log.warning(f"No expected key configured for endpoint: {path}")
            return JsonResponse({"success": False, "error": "Unauthorized endpoint."}, status=403)

        # Identify the caller (if provided)
        caller = (
            request.headers.get("X-CALLER")
            or request.META.get("HTTP_X_CALLER")
            or ""
        ).strip().lower()

        # Determine the expected key based on the caller
        if caller == "colleague":
            expected_key = getattr(settings, "COLLEAGUE_API_KEY", None)
        else:
            expected_key = getattr(settings, expected_key_setting, None)

        if not expected_key:
            log.error(f"Missing expected key in settings for {expected_key_setting} or COLLEAGUE_API_KEY")
            return JsonResponse({"success": False, "error": "Server misconfigured."}, status=500)

        # Validate incoming key
        if incoming_key != expected_key:
            log.warning(f"Invalid API key attempt on {request.path} by caller: {caller or 'default'}")
            log.warning(f"🔐 Decrypted incoming key: {repr(incoming_key)}")
            log.warning(f"🔐 Expected key from settings: {repr(expected_key)}")
            return JsonResponse({"success": False, "error": "Invalid API key."}, status=401)

        return view_func(request, *args, **kwargs)

    return _wrapped_view


def signature_required(view_func):
    def _wrapped_view(request, *args, **kwargs):
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except Exception:
            return JsonResponse({"success": False, "error": "Invalid JSON format."}, status=400)

        signature = payload.get("signature")
        if signature:  # Only validate if signature is present
            if not Utils.validate_signature_dynamic(payload):
                return JsonResponse({"success": False, "error": "Invalid signature."}, status=403)

        return view_func(request, *args, **kwargs)

    return _wrapped_view