from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from src.apps.decorators.decorators import api_key_required
from src.lib.utils.logger import Logger
from src.apps.device_registry.lib.device_registry_handler import DeviceRegistryHandler
import json, socket
# Logging ahora usa Python logging nativo
from src.lib.utils.utils import Utils

log = Logger("device_registry_views")

@csrf_exempt
@api_key_required
def RegisterDeviceView(request):
    log.info("📥 [RegisterDeviceView] Received request")

    if request.method != "POST":
        return JsonResponse({"success": False, "error": "Invalid request method."}, status=405)

    try:
        data = json.loads(request.body)
    except Exception as e:
        return JsonResponse({"success": False, "error": "Invalid JSON format."}, status=400)

    mac_input = data.get("mac")
    ip = data.get("ip")

    if not mac_input:
        return JsonResponse({"success": False, "error": "Missing parameter: mac"}, status=400)

    # Normalizamos las MACs (acepta string o lista)
    normalized_macs = Utils.normalize_mac(mac_input)

    log.info(f"📥 Normalized MAC(s): {normalized_macs} | IP: {ip}")

    # Convertimos a lista si no lo era
    macs = normalized_macs if isinstance(normalized_macs, list) else [normalized_macs]

    registered = []
    duplicates = []
    invalids = []

    for mac in macs:
        result = DeviceRegistryHandler.register_mac(mac)
        registered += result.get("registered", [])
        duplicates += result.get("duplicates", [])
        invalids += result.get("invalids", [])

        log.info(f"🔧 Result for MAC {mac} → {result}")

        # Actualiza IP si se ha indicado y el MAC ha sido registrado
        if ip and mac in result.get("registered", []):
            DeviceRegistry.objects.filter(mac=mac).update(ip=ip)

    return JsonResponse({
        "success": True,
        "registered": registered,
        "duplicates": duplicates,
        "invalids": invalids,
        "ip": ip,
        "hostname": socket.gethostname()
    }, status=200 if registered == [] else 201)


@csrf_exempt
@api_key_required
def DeviceExistsView(request):
    log.info("📥 [DeviceExistsView] Received request")

    if request.method != "GET":
        return JsonResponse({"success": False, "error": "Invalid request method."}, status=405)

    mac = request.GET.get("mac")
    if not mac:
        return JsonResponse({"success": False, "error": "Missing parameter: mac"}, status=400)

    exists = DeviceRegistryHandler.check_mac_exists(mac)

    return JsonResponse({"success": True, "exists": exists})

@csrf_exempt
@api_key_required
def UpdateDeviceView(request):
    log.info("📥 [UpdateDeviceView] Received request")

    if request.method != "POST":
        return JsonResponse({"success": False, "error": "Invalid request method."}, status=405)

    try:
        data = json.loads(request.body)
    except Exception:
        return JsonResponse({"success": False, "error": "Invalid JSON format."}, status=400)

    result = DeviceRegistryHandler.update_device(data)

    if not result["success"]:
        return JsonResponse(result, status=400)

    return JsonResponse({
        "success": True,
        "message": result["message"]
    }, status=200)
    
@csrf_exempt
@api_key_required
def RegisterInstanceCredentialsView(request):
    log.info("📥 [RegisterInstanceCredentialsView] Received request")

    if request.method != "POST":
        return JsonResponse({"success": False, "error": "Invalid method"}, status=405)

    try:
        data = json.loads(request.body)
        result = DeviceRegistryHandler.register_credentials(data)
        return JsonResponse(result, status=200 if result["success"] else 400)

    except Exception as e:
        log.error(f"💥 Exception in RegisterInstanceCredentialsView: {e}")
        return JsonResponse({"success": False, "error": str(e)}, status=500)
    
@csrf_exempt
@api_key_required
def GetAllMACsView(request):
    log.info("📥 [GetAllMACsView] Received request")

    if request.method != "GET":
        return JsonResponse({"success": False, "error": "Invalid request method."}, status=405)

    try:
        macs = DeviceRegistryHandler.get_all_macs()
        return JsonResponse({"success": True, "macs": macs})
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)

@csrf_exempt
@api_key_required
def PingView(request):
    """
    NetEncoder /ping endpoint for diagnostics.
    """
    return JsonResponse({
        "success": True,
        "message": "NetEncoder alive and kicking.",
        "host": socket.gethostname(),
        "ip": request.META.get('REMOTE_ADDR'),
    }, status=200)