from datetime import datetime
from src.lib.omnitec_crypto.omnitec_crypto import OmnitecCrypto

class Utils:
    """
    A collection of utility functions including logging, data transformation,
    and hexadecimal validation.
    """

    @staticmethod
    def log_message(level: str, message: str) -> None:
        """
        Logs a message with a timestamp.

        Args:
            level (str): Log level (INFO, DEBUG, ERROR, etc.).
            message (str): The message to be logged.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{level}] - {timestamp} - {message}")

    @staticmethod
    def transform_data_extract_nested(data_input):
        """
        Universal transformer for card data (whitelist + blacklist),
        supports both direct write and revalidation workflows.
        """
        if not isinstance(data_input, dict):
            raise TypeError("Input data must be a dictionary.")

        if "parametros" in data_input and isinstance(data_input["parametros"], dict):
            data_input = data_input["parametros"]

        regular_data = []
        blacklist_data = []

        upkey_list = data_input.get("upkeyList", [])
        for item in upkey_list:
            nested_list = item.get("list", [])
            for entry in nested_list:
                mac_raw = entry.get("mac", "")
                mac_clean = str(mac_raw).replace(":", "") if isinstance(mac_raw, str) else f"{mac_raw:08X}"

                regular_data.append({
                    "hotel_info": entry.get("hotelInfo", "") or entry.get("hotel_info", ""),
                    "_sectis_lowestor": True,
                    "build_no": entry.get("buildNo", 1),
                    "floor_no": entry.get("floorNo", 1),
                    "mac": mac_clean,
                    "timestamp": entry.get("endDate", 0) // 1000 if isinstance(entry.get("endDate", 0), int) else 0,
                    "allow_lock_out": bool(entry.get("allowLockOut", False) or entry.get("allow_lock_out", False)),
                })

            for entry in item.get("blackList", []):
                blacklist_data.append({
                    "hotelInfo": entry.get("hotelInfo", "") or entry.get("hotel_info", ""),
                    "uid": entry.get("uid", ""),
                    "endDate": entry.get("endDate", 0) // 1000 if isinstance(entry.get("endDate", 0), int) else 0,
                })

        # Also accept global blacklist for legacy fallback
        if "blackList" in data_input and isinstance(data_input["blackList"], list):
            for item in data_input["blackList"]:
                blacklist_data.append({
                    "hotelInfo": item.get("hotelInfo", "") or item.get("hotel_info", ""),
                    "uid": item.get("uid", ""),
                    "endDate": item.get("endDate", 0) // 1000 if isinstance(item.get("endDate", 0), int) else 0,
                })

        return regular_data, blacklist_data
    
    @staticmethod
    def transform_data_for_revalidate(data_input):
        """
        Extracts only the necessary whitelist and blacklist entries
        for the revalidation workflow.
        Assumes input has a 'parametros' field.
        Returns (regular_data, blacklist_data).
        """
        if not isinstance(data_input, dict):
            raise TypeError("Input data must be a dictionary.")

        if "parametros" in data_input and isinstance(data_input["parametros"], dict):
            data_input = data_input["parametros"]

        regular_data = []
        blacklist_data = []

        upkey_lists = data_input.get("upkeyList", [])
        for item in upkey_lists:
            nested_list = item.get("list", [])
            for entry in nested_list:
                mac = entry.get("mac")
                if isinstance(mac, str):
                    mac_clean = mac.replace(":", "")
                elif isinstance(mac, int):  # Allow 0 as valid
                    mac_clean = f"{mac:08X}"
                else:
                    continue  # Skip if it's neither str nor int

                regular_data.append({
                    "hotel_info": entry.get("hotelInfo", ""),
                    "_sectis_lowestor": True,
                    "build_no": entry.get("buildNo", 1),
                    "floor_no": entry.get("floorNo", 1),
                    "mac": mac_clean,
                    "timestamp": entry.get("endDate", 0) // 1000,
                    "allow_lock_out": bool(entry.get("allowLockOut", False)),
                })

            for entry in item.get("blackList", []):
                blacklist_data.append({
                    "hotelInfo": entry.get("hotelInfo", ""),
                    "uid": entry.get("uid", ""),
                    "endDate": entry.get("endDate", 0) // 1000,
                })

        return regular_data, blacklist_data

    @staticmethod
    def is_hexadecimal(value: str) -> bool:
        """
        Validates if a given string is a valid hexadecimal value.

        Args:
            value (str): The string to validate.

        Returns:
            bool: True if the value is a valid hexadecimal string; False otherwise.
        """
        try:
            int(value, 16)
            return True
        except ValueError:
            return False

    @staticmethod
    def check_card_not_blacklisted(ip_address, port, blacklist_objects):
        """
        Checks if the current card is blacklisted. Checks Card's UID agains the blacklist of UIDs 
        IN case of a match, an exception is raised to abort the operation to protect the card
        """
        from src.lib.hf_reader_dll.hf_reader_dll_service import HFReaderDLLService
   
        # Create an instance of HFReaderDLLService
        reader_service = HFReaderDLLService()
        
        # Read the card UID
        uid_response = reader_service.read_card_uid(ip_address, port)
        
        # Check if the read was successful
        if not uid_response.get("success", False):
            raise Exception(f"Failed to read card UID: {uid_response.get('error', 'Unknown error')}")
        
        # Get the UID and convert to uppercase
        card_uid = uid_response.get("uid", "").upper().strip()
        
        # Check against blacklist
        for entry in blacklist_objects:
            bl_uid = entry.get("uid", "").upper().strip()
            if bl_uid and bl_uid == card_uid:
                raise Exception(f"ABORTING FOR CARD SAFETY! Current card UID {card_uid} is blacklisted!")
                
        return True
    
    # @staticmethod
    # def normalize_mac(mac: str) -> str:
    #     if not mac:
    #         return ""
    #     return mac.replace(":", "").replace("-", "").replace(".", "").upper()
    
    @staticmethod
    def normalize_mac(mac: str | list[str]) -> str | list[str]:
        if not mac:
            return ""

        def clean(m):
            return m.replace(":", "").replace("-", "").replace(".", "").upper()

        if isinstance(mac, list):
            return [clean(m) for m in mac]
        
        return clean(mac)    

    @staticmethod
    def sign(last_func: str, err_code: int, uid: str) -> str:
        try:
            concatenated = f"{last_func}{err_code}{uid}"
            print(f"🧾 Concatenated string: {concatenated}")
            print(f"📏 Length: {len(concatenated)}")
            encrypted = OmnitecCrypto.encrypt(concatenated)
            print(f"🔐 Signature: {encrypted}")
            print(f"📏 Signature length: {len(encrypted)}")
            return encrypted
        except Exception as e:
            print(f"❌ Error during signing: {e}")
            return "SIGN_ERROR"
        
    @staticmethod
    def validate_signature_dynamic(payload: dict) -> bool:
        """
        Validate signature by:
        - Finding the 'signature' key
        - Concatenating all fields before it
        - Comparing decrypted signature with that concatenation
        """
        try:
            keys = list(payload.keys())
            if "signature" not in keys:
                return False

            sig_index = keys.index("signature")
            fields_to_concat = keys[:sig_index]

            concatenated = "".join(str(payload[k]) for k in fields_to_concat)
            encrypted = payload["signature"]
            decrypted = OmnitecCrypto.decrypt(encrypted)

            return decrypted == concatenated
        except Exception as e:
            print(f"🔐 Signature validation failed: {e}")
            return False