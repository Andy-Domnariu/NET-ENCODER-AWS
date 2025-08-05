import sys, os, json, time, requests, threading, socket
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from src.lib.utils.logger import Logger
from src.apps.decorators.decorators import signature_required
from typing import Dict, Any, Optional
from src.lib.hf_reader_dll.hf_reader_dll_service import HFReaderDLLService
from src.apps.net_encoder.lib.net_encoder_handler import NetEncoderHandler
from src.lib.utils.utils import Utils

log = Logger("api_views")

@csrf_exempt
# @api_key_required
# @signature_required
def ReadCardUIDView(request) -> JsonResponse:
    """Retrieve the UID of a card and respond like OSAccess expects."""
    log.info("📥 Received request: ReadCardUIDView")

    start_time = time.time()
    if request.method != "POST":
        return JsonResponse({"success": False, "error": "Invalid request method."}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8"))
        print(f"🔑 Data: {data}")
        ip_address = data.get("ip_address")
        port = data.get("port")
        use_acr = data.get("useACR", "1")
        hotel_info = data.get("hotelInfo", "")
        upkey_sectors = data.get("upkeySectors", "")
        print(f"🔑 Use ACR: {use_acr}")
        print(f"🔑 Hotel Info: {hotel_info}")
        print(f"🔑 Upkey Sectors: {upkey_sectors}")

        if not ip_address or not port:
            return JsonResponse({"success": False, "error": "Missing ip_address or port."}, status=400)

        port = int(port)
        service = HFReaderDLLService()
        response_data = service.read_card_uid(ip_address, port)

        if not response_data.get("success", False):
            log.error(f"❌ Error reading card UID: {response_data.get('error')}")
            return JsonResponse({"success": False, "error": response_data.get("error")}, status=400)

        uid = response_data["uid"].upper()
        signature = Utils.sign("read_card_uid", 0, uid)
        print(f"🔑 Signature: {signature}")
        hostname = socket.gethostname()

        osaccess_response = {
            "lastFunc": "read_card_uid",
            "errCode": 0,
            "uid": uid,
            "signature": signature,
            "versionCardOsaccess": "1.0.1",
            "hostName": hostname
        }

        end_time = time.time()
        log.info(f"✅ ReadCardUIDView completed in {end_time - start_time:.2f}s")

        return JsonResponse(osaccess_response)

    except Exception as e:
        log.error(f"❌ Unexpected error in ReadCardUIDView: {e}")
        return JsonResponse({"success": False, "error": str(e)}, status=500)

    finally:
        log.info("📤 Request processing completed.")


@csrf_exempt        
# @api_key_required    
@signature_required
def ReadCardView(request) -> JsonResponse:
    """
    Django view for reading a Mifare 1K card via POST request.

    Expects a JSON request body with:
        - ip_address (str): IP of the HF reader.
        - port (int): Port of the HF reader.
        - ic_key (str, optional): Encrypted IC key.

    Returns:
        JSON response with block data or an error message.
    """
    if request.method != "POST":
        return JsonResponse({"success": False, "error": "Invalid request method."}, status=405)

    try:
        # Parse JSON body
        try:
            data = json.loads(request.body.decode("utf-8"))
        except json.JSONDecodeError:
            return JsonResponse({"success": False, "error": "Invalid JSON format."}, status=400)

        # Extract expected parameters
        ip_address = data.get("ip_address")
        port = data.get("port")
        ic_key = data.get("ic_key")

        if not ip_address or not port:
            return JsonResponse({"success": False, "error": "Missing ip_address or port."}, status=400)

        port = int(port)  # Ensure port is an integer
        service = HFReaderDLLService()
        response_data = service.read_card_data(ip_address, port, [ic_key] if ic_key else None)

        # ✅ Ensure JSON does not modify valid hex data
        formatted_data = {
            block: data if data not in [None, "READ_FAIL"] else "FAILED"
            for block, data in response_data.items()
        }

        return JsonResponse({"success": True, "data": formatted_data}, status=200)

    except Exception as e:
        log.error(f"Unexpected error in ReadCardView: {e}")
        return JsonResponse({"success": False, "error": str(e)}, status=500)
    
@csrf_exempt
# @api_key_required
# @signature_required
def WriteCardView(request) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"success": False, "error": "Invalid request method."}, status=405)
    try:
        raw_data: Dict[str, Any] = json.loads(request.body.decode("utf-8"))
        ip_address: str = raw_data.get("ip_address")
        port = raw_data.get("port")
        encrypted_ic_key: str = raw_data.get("icKey") or raw_data.get("ic_key")

        missing_params = []
        if not ip_address:
            missing_params.append("ip_address")
        if not port:
            missing_params.append("port")
        if not encrypted_ic_key:
            missing_params.append("icKey")

        if missing_params:
            return JsonResponse({"success": False, "error": f"Missing required parameters: {missing_params}"}, status=400)

        try:
            port = int(port)
        except ValueError:
            return JsonResponse({"success": False, "error": "Invalid port number."}, status=400)

        handler = NetEncoderHandler()
        result = handler.write_card_data(ip_address, port, encrypted_ic_key, raw_data)

        if not result.get("success"):
            return JsonResponse({"success": False, "error": result.get("error", "Write failed.")}, status=400)

        uid = result.get("uid", "").upper()
        last_func = "write_card_data"
        err_code = 0
        signature = Utils.sign(last_func, err_code, uid)

        return JsonResponse({
            "lastFunc": last_func,
            "errCode": err_code,
            "uid": uid,
            "signature": signature,
            "versionNetEncoder": "1.0.1",
            "hostName": socket.gethostname()
        })

    except json.JSONDecodeError:
        return JsonResponse({"success": False, "error": "Invalid JSON format."}, status=400)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@csrf_exempt
# @api_key_required
@signature_required
def ResetCardView(request) -> JsonResponse:
    """
    Django view for resetting a Mifare 1K card.
    Expects a POST request with:
      - ip_address (str): Encoder IP address.
      - port (int): Encoder port.
      - ic_key (str, optional): Encrypted IC key.
    Returns a JSON response with reset status.
    """
    if request.method != "POST":
        return JsonResponse({"success": False, "error": "Invalid request method."}, status=405)
    
    handler = None
    try:
        data: Dict[str, Any] = json.loads(request.body.decode("utf-8"))
        ip_address: Optional[str] = data.get("ip_address")
        port = data.get("port")
        ic_key: Optional[str] = data.get("ic_key") or data.get("icKey")

        # Validate required parameters
        missing_fields = []
        if not ip_address:
            missing_fields.append("ip_address")
        if not port:
            missing_fields.append("port")

        if missing_fields:
            log.error(f"Missing required parameters: {missing_fields}")
            return JsonResponse(
                {"success": False, "error": f"Missing required parameters: {missing_fields}"},
                status=400
            )

        port = int(port)
        log.info(f"Resetting card at {ip_address}:{port} with ic_key={ic_key}")

        # Initialize NetEncoderHandler
        handler = NetEncoderHandler()   

        # Execute reset process
        response_data = handler.write_reset_data(ip_address, port, ic_key)
        return JsonResponse(response_data)

    except json.JSONDecodeError:
        log.error("Invalid JSON format in request.")
        return JsonResponse({"success": False, "error": "Invalid JSON format."}, status=400)
    except Exception as e:
        log.error(f"Unexpected error in ResetCardView: {e}")
        return JsonResponse({"success": False, "error": str(e)}, status=500)
    finally:
        log.info("ResetCardView: Request processing completed.")
