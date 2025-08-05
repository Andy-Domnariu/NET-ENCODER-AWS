import sys, os, json, time
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../..")))
# Logging ahora usa Python logging nativo
from src.lib.omnitec_crypto.omnitec_crypto import OmnitecCrypto
from src.lib.card_encoder_dll.card_encoder_dll_service import CardEncoderDLLService
from src.lib.hf_reader_dll.hf_reader_dll_service import HFReaderDLLService
from src.lib.utils.utils import Utils
from src.lib.utils.logger import Logger

# Configurable logging levels

log = Logger("net_encoder_handler")

class NetEncoderHandler:
        
    @staticmethod
    def read_card_uid(ip_address: str, port: int) -> dict:
        """Retrieves the UID of the card."""
        log.info(f"Reading card UID from {ip_address}:{port}")

        hf_reader_dll_service = HFReaderDLLService()
        return hf_reader_dll_service.read_card_uid(ip_address, port)

    @staticmethod
    def read_card_data(ip_address: str, port: int, encrypted_ic_key: str) -> dict:
        """Reads the full card data, passing IC key as a list."""
        log.info(f"Encrypted IC key: {encrypted_ic_key}")

        decrypted_ic_key = OmnitecCrypto.decrypt(encrypted_ic_key)
        
        log.info(f"Decrypted IC key: {decrypted_ic_key}")
        
        if not decrypted_ic_key:
            return {"success": False, "error": "Invalid IC key."}

        log.info(f"Starting read_card_data with ip_address={ip_address}, port={port}")

        hf_reader_dll_service = HFReaderDLLService()
        return hf_reader_dll_service.read_card_data(ip_address, port, [decrypted_ic_key])

    # @staticmethod
    # def write_card_data(ip_address: str, port: int, encrypted_ic_key: str, raw_data_input) -> dict:
    #     """Handles writing card data, ensuring correct transformation and validation."""
    #     if LOG_INFO:
    #         log.info(f"Starting write_card_data with ip_address={ip_address}, port={port}")

    #     decrypted_ic_key = OmnitecCrypto.decrypt(encrypted_ic_key)
    #     if not decrypted_ic_key:
    #         return {"success": False, "error": "Missing or invalid decrypted IC key."}

    #     card_uid = ""
    #     try:
    #         uid_response = NetEncoderHandler.read_card_uid(ip_address, port)
    #         card_uid = uid_response.get("uid", "") if uid_response.get("success") else ""
    #     except Exception as e:
    #         if LOG_WARNING:
    #             log.warning(f"Error reading card UID: {e}, continuing without it")

    #     try:
    #         raw_data_dict = json.loads(raw_data_input) if isinstance(raw_data_input, str) else raw_data_input
    #         regular_data, blacklist_data = Utils.transform_data_extract_nested(raw_data_dict)
    #     except Exception as e:
    #         if LOG_ERROR:
    #             log.error(f"Data transformation error: {e}")
    #         return {"success": False, "error": f"Data transformation error: {e}"}

    #     if not regular_data:
    #         if LOG_INFO:
    #             log.info("⚠️ 'upkeyList' is missing or empty. Skipping card writing.")
    #         return {"success": True, "uid": card_uid, "blocks": {}}

    #     encoder_service = CardEncoderDLLService()
    #     hotel_info_val = regular_data[0].get("hotel_info", "")

    #     formatted_data_blocks = encoder_service.generate_card_data(
    #         hotel_info=hotel_info_val,
    #         card_uid=card_uid,
    #         whitelist_data=regular_data,
    #         blacklist_data=blacklist_data
    #     )

    #     if not formatted_data_blocks:
    #         if LOG_ERROR:
    #             log.error("Formatted sector data is empty. Aborting write process.")
    #         return {"success": False, "error": "No formatted sector data available."}

    #     ic_keys_list = [decrypted_ic_key]
    #     hf_reader_service = HFReaderDLLService()
    #     write_result = hf_reader_service.write_card_data(ip_address, port, formatted_data_blocks, ic_keys_list)

    #     return {
    #         "success": write_result.get("success", False),
    #         "uid": write_result.get("uid", card_uid),
    #         "blocks": write_result.get("blocks", {}),
    #         "error": write_result.get("error")
    #     }
    
    @staticmethod
    def write_card_data(ip_address: str, port: int, encrypted_ic_key: str, raw_data_input) -> dict:
    
        log.info(f"📝 Starting write_card_data for {ip_address}:{port}")

        decrypted_ic_key = OmnitecCrypto.decrypt(encrypted_ic_key)
        log.info(f"🔓 Decrypted ICKEY: {decrypted_ic_key}")

        if not decrypted_ic_key:
            log.error("❌ Missing or invalid decrypted IC key.")
            return {"success": False, "error": "Missing or invalid decrypted IC key."}

        card_uid = ""
        try:
            uid_response = NetEncoderHandler.read_card_uid(ip_address, port)
            if uid_response.get("success"):
                card_uid = uid_response.get("uid", "")
                log.info(f"📚 Card UID obtained: {card_uid}")
            else:
                log.warning(f"⚠️ Failed to get UID: {uid_response.get('error')}")
        except Exception as e:
            log.warning(f"⚠️ Exception reading card UID: {e}")

        try:
            raw_data_dict = json.loads(raw_data_input) if isinstance(raw_data_input, str) else raw_data_input
            regular_data, blacklist_data = Utils.transform_data_extract_nested(raw_data_dict)
        except Exception as e:
            log.error(f"🚫 Data transformation error: {e}")
            return {"success": False, "error": f"Data transformation error: {e}"}

        if not regular_data:
            log.info("⚠️ No 'upkeyList' data found. Skipping write.")
            return {"success": True, "uid": card_uid, "blocks": {}}

        encoder_service = CardEncoderDLLService()
        hotel_info_val = regular_data[0].get("hotel_info", "")

        formatted_data_blocks = encoder_service.generate_card_data(
            hotel_info=hotel_info_val,
            card_uid=card_uid,
            whitelist_data=regular_data,
            blacklist_data=blacklist_data
        )

        if not formatted_data_blocks:
            log.error("❌ No formatted sector data. Aborting write process.")
            return {"success": False, "error": "No formatted sector data available."}

        log.info(f"📦 Generated data blocks for writing: {formatted_data_blocks}")

        ic_keys_list = [decrypted_ic_key]
        hf_reader_service = HFReaderDLLService()
        write_result = hf_reader_service.write_card_data(ip_address, port, formatted_data_blocks, ic_keys_list)

        return {
            "success": write_result.get("success", False),
            "uid": write_result.get("uid", card_uid),
            "blocks": write_result.get("blocks", {}),
            "error": write_result.get("error")
        }


    #---------------------------------------processing time metrics for each step-----------------------------------------
    # @staticmethod
    # def write_card_data(ip_address: str, port: int, encrypted_ic_key: str, raw_data_input) -> dict:
    #     timings = {}
    #     t0 = time.perf_counter()

    #     # Step 1: Decrypt IC key
    #     decrypted_ic_key = OmnitecCrypto.decrypt(encrypted_ic_key)
    #     timings["decrypt_ic_key"] = time.perf_counter() - t0

    #     if not decrypted_ic_key:
    #         return {"success": False, "error": "Missing or invalid decrypted IC key."}

    #     # Step 2: Parse & transform input
    #     t1 = time.perf_counter()
    #     try:
    #         raw_data_dict = json.loads(raw_data_input) if isinstance(raw_data_input, str) else raw_data_input
    #         regular_data, blacklist_data = Utils.transform_data_extract_nested(raw_data_dict)
    #     except Exception as e:
    #         return {"success": False, "output": f"Data transformation error: {e}"}
    #     timings["transform_data"] = time.perf_counter() - t1

    #     if not regular_data:
    #         return {"success": False, "output": "No regular card data found."}

    #     # Step 3: Read card UID
    #     t2 = time.perf_counter()
    #     card_uid = ""
    #     try:
    #         uid_response = HFReaderDLLService().read_card_uid(ip_address, port)
    #         if uid_response.get("success"):
    #             card_uid = uid_response.get("uid", "")
    #     except Exception as e:
    #         log.warning(f"⚠️ UID read failed: {e}")
    #     timings["read_card_uid"] = time.perf_counter() - t2

    #     # Step 4: Generate card data blocks
    #     t3 = time.perf_counter()
    #     encoder_service = CardEncoderDLLService()
    #     hotel_info_val = regular_data[0].get("hotel_info", "")
    #     formatted_data_blocks = encoder_service.generate_card_data(
    #         hotel_info=hotel_info_val,
    #         card_uid=card_uid,
    #         whitelist_data=regular_data,
    #         blacklist_data=blacklist_data
    #     )
    #     timings["generate_card_data"] = time.perf_counter() - t3

    #     if not formatted_data_blocks:
    #         return {"success": False, "output": "No formatted sector data available."}

    #     # Step 5: Write card data
    #     t4 = time.perf_counter()
    #     hf_reader_service = HFReaderDLLService()
    #     ic_keys_list = [decrypted_ic_key]
    #     write_success = hf_reader_service.write_card_data(ip_address, port, formatted_data_blocks, ic_keys_list)
    #     timings["write_card_data"] = time.perf_counter() - t4

    #     # Final timing
    #     timings["total"] = time.perf_counter() - t0

    #     log.info("\n⏱ Step-by-step timing (in seconds):\n" + json.dumps(timings, indent=2))

    #     return {
    #         "success": write_success,
    #         "uid": card_uid,
    #         "data": formatted_data_blocks if write_success else None,
    #         "output": "Card written successfully." if write_success else "Failed to write card."
    #     }
    #------------------------------------------------------------------------------------------------------------------
        
    @staticmethod
    def write_reset_data(ip_address: str, port: int, encrypted_ic_key: str) -> dict:
        """Resets a card by writing zeros to all sectors."""
        log.info(f"Starting write_reset_data with ip_address={ip_address}, port={port}")
        
        decrypted_ic_key = OmnitecCrypto.decrypt(encrypted_ic_key)
        
        log.info(f"Decrypted IC key: {decrypted_ic_key}")
        
        if not decrypted_ic_key:
            return {"success": False, "error": "Invalid decrypted IC key format."}

        hf_reader_service = HFReaderDLLService()
        reset_success = hf_reader_service.write_reset_data(ip_address, port, decrypted_ic_key)

        if not reset_success or not reset_success.get("success", False):  # ✅ safer check
            log.error("Failed to reset card data.")
            return {"success": False, "output": "Failed to reset card data."}

        log.info("Card reset successfully.")
        return {
            "success": True,
            "output": "Card reset successfully.",
            "uid": reset_success.get("uid"),
            "details": reset_success.get("details")  # optional: expose block statuses
        }



