import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from src.lib.utils.logger import Logger
from src.lib.hf_reader_dll.hf_reader_poller_manager import PollerManager
from src.lib.hf_reader_dll.hf_reader_dll_service import HFReaderDLLService

log = Logger("RevalidateCardView")

@csrf_exempt
def RevalidateCardView(request):
    """
    Django view to handle card revalidation process via RevalidatorHandler.
    """
    if request.method != "POST":
        return JsonResponse({"success": False, "error": "Method not allowed. Use POST."}, status=405)

    try:
        payload = json.loads(request.body.decode("utf-8"))
        log.info(f"📥 Incoming revalidation payload: {payload}")

        handler = HFReaderDLLService()
        result = handler.revalidate_card_workflow(payload)
        return JsonResponse(result, status=200 if result.get("success") else 400)

    except json.JSONDecodeError:
        log.error("❌ Invalid JSON received in revalidation view.")
        return JsonResponse({"success": False, "error": "Invalid JSON format."}, status=400)

    except Exception as e:
        log.error(f"💥 Unhandled exception in RevalidateCardView: {e}")
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@csrf_exempt
def PollerStartAllView(request):
    """
    POST /revalidator/poller/start-all/
    """
    if request.method != "POST":
        return JsonResponse({"success": False, "error": "Invalid method"}, status=405)

    # You could require an API-key or signature decorator here if you like
    sleep_seconds = None
    try:
        data = json.loads(request.body.decode())
        sleep_seconds = float(data.get("sleep_seconds", 1.0))
    except Exception:
        sleep_seconds = 1.0

    PollerManager.start_all_polling(sleep_seconds=sleep_seconds)
    return JsonResponse({
        "success": True,
        "message": f"Polling started for all revalidator readers (interval={sleep_seconds}s)"
    })

@csrf_exempt
def PollerStopAllView(request):
    """
    POST /revalidator/poller/stop-all/
    """
    if request.method != "POST":
        return JsonResponse({"success": False, "error": "Invalid method"}, status=405)

    PollerManager.stop_all_polling()
    return JsonResponse({
        "success": True,
        "message": "Polling stopped for all revalidator readers"
    })