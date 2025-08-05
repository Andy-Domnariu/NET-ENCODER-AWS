from src.lib.utils.logger import Logger
import sys, os, ctypes, time, socket
import threading, concurrent.futures

from src.lib.hf_reader_dll.hf_threadmanager import HFReaderDLLManager
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
from time import sleep
from ctypes import c_long, c_ubyte, c_char_p, POINTER, byref, cast
from typing import Optional, Tuple, Dict, Any, List, Union

log = Logger("hf_reader_dll_interface")

def log_elapsed(fn):
    def wrapper(self, *args, **kwargs):
        if LOG_ELAPSED_TIME:
            start = time.time()
        result = fn(self, *args, **kwargs)
        if LOG_ELAPSED_TIME:
            elapsed = time.time() - start
            log.debug(f"{fn.__name__} elapsed {elapsed:.3f}s")  # Usar DEBUG para tiempos de ejecución
        return result
    return wrapper

# Configurable constants.
# RETRY_DELAY = 0  # seconds.
# MAX_CONNECT_RETRIES = 1
LOG_ELAPSED_TIME = True  # Mantener este FLAG solo para el decorator log_elapsed

    
class HFReaderDLLInterface:
    """
    Interface to interact with the HFReader via a DLL.
    This class loads the DLL, defines function signatures for card operations,
    and manages the connection via the 'connect' and 'disconnect' methods.
    """

    _instance = None  # Singleton instance


    # Error codes for general operations.
    GENERAL_ERRORS: Dict[int, str] = {
        0: "OK",
        16: "ISO14443A operation error",
        53: "Port is open",
        54: "Port is closed",
        48: "Communication error. You may be entering the wrong IP or port. Also the net port may be closed",
        55: "Invalid port handle",
    }

    # Error codes for ISO14443A operations.
    ISO14443A_ERRORS: Dict[int, str] = {
        32: "No active ISO14443A tag in RF field. Ensure a card is on the reader.", 
        33: "Tag selection failed. Ensure card is readable / functional.",
        34: "Authentication failed. You could be using the wrong key",
        35: "Read failed. You could be using a block from an unauthenticated sector",
        36: "Write failed. You could be using a block from an unauthenticated sector",
    }
    
    @staticmethod
    def configure_logging_level(level: str = 'INFO'):
        """
        Configura el nivel de logging para el módulo HFReader.
        Niveles disponibles: DEBUG, INFO, WARNING, ERROR
        
        DEBUG: Muestra toda la información incluyendo tiempos de ejecución
        INFO: Muestra información general y mensajes importantes
        WARNING: Solo advertencias y errores
        ERROR: Solo errores
        """
        log.set_level(level)
        print(f"🔧 Nivel de logging configurado a: {level}")
    
    @log_elapsed    
    def __init__(self, ip: str, port:int, dll_path: str = "dll\\HFReader.dll") -> None:
        self.hf_reader_dll = HFReaderDLLManager.get_for_ip(ip,port)
       
        """
        Initialize the HFReaderDLLInterface instance by loading the DLL and
        initializing internal connection attributes.

        :param dll_path: Path to the HFReader DLL.
        :raises RuntimeError: If the DLL cannot be loaded.
        """
        try:    
            print("comenzando instancia de interface")
            # self.hf_reader_dll = ctypes.CDLL(dll_path)
        except Exception as e:
            log.error(f"Error loading DLL '{dll_path}': {e}")
            raise RuntimeError(f"Failed to load DLL: {dll_path}") from e

        self.com_addr: Optional[int] = None
        self.frm_handle: Optional[int] = None
        self.uid_hex: Optional[str] = None

        self._define_function_signatures()

    @log_elapsed
    def _define_function_signatures(self) -> None:
        """
        Define the argument and return types for each DLL function.
        """
        # OpenNetPort.
        self.hf_reader_dll.OpenNetPort.argtypes = [
            c_long,
            c_char_p,
            POINTER(c_ubyte),
            POINTER(c_long),
        ]
        self.hf_reader_dll.OpenNetPort.restype = c_long
        

        # CloseNetPort.
        self.hf_reader_dll.CloseNetPort.argtypes = [c_long]
        self.hf_reader_dll.CloseNetPort.restype = c_long

        # SetBeep.
        self.hf_reader_dll.SetBeep.argtypes = [
            POINTER(c_ubyte),
            c_ubyte,
            c_ubyte,
            c_ubyte,
            c_long,
        ]
        self.hf_reader_dll.SetBeep.restype = c_long

        # OpenRf.
        self.hf_reader_dll.OpenRf.argtypes = [POINTER(c_ubyte), c_long]
        self.hf_reader_dll.OpenRf.restype = c_long

        # CloseRf.
        self.hf_reader_dll.CloseRf.argtypes = [POINTER(c_ubyte), c_long]
        self.hf_reader_dll.CloseRf.restype = c_long

        # GetReaderInformation.
        self.hf_reader_dll.GetReaderInformation.argtypes = [
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_long,
        ]
        self.hf_reader_dll.GetReaderInformation.restype = c_long

        # ChangeTo14443A.
        self.hf_reader_dll.ChangeTo14443A.argtypes = [POINTER(c_ubyte), c_long]
        self.hf_reader_dll.ChangeTo14443A.restype = c_long

        # ISO14443ARequest.
        self.hf_reader_dll.ISO14443ARequest.argtypes = [
            POINTER(c_ubyte),
            c_ubyte,
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_long,
        ]
        self.hf_reader_dll.ISO14443ARequest.restype = c_long

        # ISO14443AAnticoll.
        self.hf_reader_dll.ISO14443AAnticoll.argtypes = [
            POINTER(c_ubyte),
            c_ubyte,
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_long,
        ]
        self.hf_reader_dll.ISO14443AAnticoll.restype = c_long

        # ISO14443ASelect.
        self.hf_reader_dll.ISO14443ASelect.argtypes = [
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_long,
        ]
        self.hf_reader_dll.ISO14443ASelect.restype = c_long

        # ISO14443AAuthKey.
        self.hf_reader_dll.ISO14443AAuthKey.argtypes = [
            POINTER(c_ubyte),
            c_ubyte,
            c_ubyte,
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_long,
        ]
        self.hf_reader_dll.ISO14443AAuthKey.restype = c_long

        # ISO14443ARead.
        self.hf_reader_dll.ISO14443ARead.argtypes = [
            POINTER(c_ubyte),
            c_ubyte,
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_long,
        ]
        self.hf_reader_dll.ISO14443ARead.restype = c_long

        # ISO14443AWrite.
        self.hf_reader_dll.ISO14443AWrite.argtypes = [
            POINTER(c_ubyte),
            c_ubyte,
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_long,
        ]
        self.hf_reader_dll.ISO14443AWrite.restype = c_long

    @log_elapsed
    def _handle_result(
        self, function_name: str, result: int, error_code: Optional[int] = None
    ) -> None:
        """
        Handle an error by logging the error message.

        :param function_name: Name of the function that failed.
        :param result: Result code of the function.
        """
        if result != 0:
            if error_code is None:
                raise Exception(
                    f"Error calling '{function_name}': {result}: {self.GENERAL_ERRORS.get(result, 'Unknown error')}."
                )
            else:
                raise Exception(
                    f"Error calling '{function_name}': {result}: {self.GENERAL_ERRORS.get(result, 'Unknown error')} ({error_code}: {self.ISO14443A_ERRORS.get(error_code, 'Unknown error')})."
                )
     
    
    @log_elapsed
    def open_net_port(self, port: int, ip_address: str) -> Tuple[int, int]:
        """Call to subprocess to open the port and return com_addr and frm_handle."""
        thread_id = threading.get_ident()
        process_id = os.getpid()
        log.info(f"🧵 Thread ID: {thread_id}, 🧠 Process ID: {process_id}")
        log.info(f"📦 DLL object id: {id(self.hf_reader_dll)}")
        # if self.frm_handle is not None:
        #     self.close_net_port(self.frm_handle)
        #     self.frm_handle = None
        #     self.com_addr = None

        # ⚠️ Aquí no usamos ctypes
        result, com_addr, frm_handle = self.hf_reader_dll.OpenNetPort(port, ip_address)

        if result != 0:
            log.error(f"❌ Failed to open network port {port}. DLL returned error {result}")
            return None, None

        return com_addr, frm_handle

    @log_elapsed
    def close_net_port(self, frm_handle: int) -> bool:
        """
        Closes the network port.
        """
        if frm_handle is None:
            log.warning("Attempted to close network port, but frm_handle=None. Skipping.")
            return False

        if self.com_addr is not None and self.frm_handle is not None:
            try:
                log.info("Closing RF before closing network port...")
                self.close_rf(self.com_addr, frm_handle)
            except Exception as e:
                log.warning(f"Failed to close RF before port close: {e}")

        log.info(f"Closing network port with frame handle {frm_handle}...")

        result = self.hf_reader_dll.CloseNetPort(frm_handle)

        if result == 0:
            log.info(f"Successfully closed network port {frm_handle}.")
            return True
        else:
            log.error(f"Failed to close network port {frm_handle}. DLL returned error {result}")
            return False

    @log_elapsed
    def open_rf(self, com_addr: int, frm_handle: int) -> bool:
        """
        Enables the RF field of the reader.

        :param com_addr: The communication address.
        :param frm_handle: The frame handle.
        :return: True if the RF field was enabled successfully, False otherwise.
        """
        log.info("Enabling RF field...")
        result = self.hf_reader_dll.OpenRf(com_addr, frm_handle)
        self._handle_result("OpenRf", result)
        return True

    @log_elapsed
    def close_rf(self, com_addr: int, frm_handle: int) -> bool:
        """
        Disables the RF field of the reader.

        :param com_addr: The communication address.
        :param frm_handle: The frame handle.
        :return: True if the RF field was disabled successfully, False otherwise.
        """
        log.info("Disabling RF field...")
        result = self.hf_reader_dll.CloseRf(com_addr, frm_handle)
        self._handle_result("CloseRf", result)
        return True

    @log_elapsed
    def change_to_14443a(self, com_addr: int, frm_handle: int) -> bool:
        """
        Switches the reader mode to ISO14443A.

        :param com_addr: The communication address.
        :param frm_handle: The frame handle.
        :return: True if the reader mode was switched successfully, False otherwise.
        """
        log.info("Switching reader mode to ISO14443A...")

        result = self.hf_reader_dll.ChangeTo14443A(com_addr, frm_handle)
        self._handle_result("ChangeTo14443A", result)
        return True

    @log_elapsed
    def iso14443a_request(self, com_addr: int, mode: int, frm_handle: int) -> bool:
        """
        Sends a request to detect an ISO14443A tag.

        :param com_addr: The communication address.
        :param mode: The request mode (0 or 1).
        :param frm_handle: The frame handle.
        :return: bool: True if the request was successful, False otherwise.
        """
        result, error_code = self.hf_reader_dll.ISO14443ARequest(com_addr, mode, frm_handle)
        self._handle_result("ISO14443ARequest", result, error_code)
        return True

    @log_elapsed
    def iso14443a_anticoll(self, com_addr: int, frm_handle: int) -> str:
        """
        Performs an anti-collision procedure to retrieve the tag UID.

        :param com_addr: The communication address.
        :param frm_handle: The frame handle.
        :return: uid: Hexadecimal UID of the detected tag.
        """
        result, error_code, uid_hex = self.hf_reader_dll.ISO14443AAnticoll(com_addr, frm_handle)
        self._handle_result("ISO14443AAnticoll", result, error_code)
        self.uid_hex = uid_hex
        return uid_hex

    @log_elapsed
    def iso14443a_select(self, com_addr: int, uid_hex: str, frm_handle: int) -> bool:
        """
        Selects an ISO14443A tag using its UID.

        :param com_addr: The communication address.
        :param uid: The UID of the tag (hexadecimal string).
        :param frm_handle: The frame handle.
        :return: True if the tag was selected successfully, False otherwise.
        """
        result, error_code = self.hf_reader_dll.ISO14443ASelect(com_addr, uid_hex, frm_handle)
        self._handle_result("ISO14443ASelect", result, error_code)
        return True

    @log_elapsed
    def iso14443a_auth_key(
        self, com_addr: int, mode: int, sector: int, key_hex: str, frm_handle: int
    ) -> bool:
        log.info(f"Authenticating sector {sector} with ICKEY {key_hex} (mode: {'Key A' if mode == 0 else 'Key B'})")
        result, error_code = self.hf_reader_dll.ISO14443AAuthKey(com_addr, mode, sector, key_hex, frm_handle)
        self._handle_result("ISO14443AAuthKey", result, error_code)
        return True


    @log_elapsed
    def iso14443a_read(self, com_addr: int, block_num: int, frm_handle: int) -> str:
        """
        Reads a 16-byte block of data from the tag.

        :param com_addr: The communication address.
        :param block_num: The block number to read.
        :param frm_handle: The frame handle.
        :return: data_hex: Hexadecimal string containing the block data.
        """
        result, error_code, raw_data = self.hf_reader_dll.ISO14443ARead(com_addr, block_num, frm_handle)
        self._handle_result("ISO14443ARead", result, error_code)
        return raw_data

    # def iso14443a_write(
    #     self, com_addr: int, block_num: int, data_hex: str, frm_handle: int
    # ) -> str:
    #     """
    #     Writes a 16-byte block of data to the tag.

    #     :param com_addr: The communication address.
    #     :param block_num: The block number to write.
    #     :param data: The 16-byte data to write (hexadecimal string).
    #     :param frm_handle: The frame handle.
    #     :return: data_hex: Hexadecimal string containing the written data.
    #     """
    #     data_bytes = bytes.fromhex(data_hex)
    #     if len(data_bytes) != 16:
    #         raise ValueError("Data must be exactly 16 bytes.")
    #     log.info(f"Writing to block {block_num} with data: {data_hex}...")
    #     result = self.hf_reader_dll.ISO14443AWrite(com_addr, block_num, data_hex, frm_handle)
    #     log.info(f"ISO14443AWrite returned {result} for block {block_num}")

    #     if result != 0:
    #         raise Exception(f"ISO14443AWrite failed (code {result})")
    #     return data_hex
    
    @log_elapsed
    def iso14443a_write(
        self, 
        com_addr: int, 
        block_num: int, 
        data_hex: str, 
        frm_handle: int
    ) -> str:
        """
        Writes a 16-byte block of data to the tag.

        :param com_addr: The communication address.
        :param block_num: The block number to write.
        :param data_hex: The 16-byte data to write (hexadecimal string).
        :param frm_handle: The frame handle.
        :return: data_hex: Hexadecimal string containing the written data.
        :raises Exception: If the DLL indicates failure.
        """
        # 1) Validate length
        data_bytes = bytes.fromhex(data_hex)
        if len(data_bytes) != 16:
            raise ValueError("Data must be exactly 16 bytes (32 hex characters).")

        log.info(f"Writing to block {block_num} with data: {data_hex}…")

        # 2) Call the DLL and capture exactly what it returns
        raw_ret = self.hf_reader_dll.ISO14443AWrite(com_addr, block_num, data_hex, frm_handle)
        log.info(f"ISO14443AWrite returned raw_ret={raw_ret!r} (type={type(raw_ret).__name__})")

        # 3) Boolean path: True means OK, False means fail
        if type(raw_ret) is bool:
            if not raw_ret:
                raise Exception("ISO14443AWrite returned False (write failed).")
            # True → success
            return data_hex

        # 4) Integer path: 0 means success, anything else is an error code
        if isinstance(raw_ret, int):
            code = raw_ret
            # Map your known error codes here, e.g. self.ISO14443A_ERRORS
            err_msg = getattr(self, "ISO14443A_ERRORS", {}).get(code, "Unknown error")
            if code != 0: 
                raise Exception(f"ISO14443AWrite failed (code {code}: {err_msg})")
            return data_hex

        # 5) Unexpected return type
        log.warning(f"Unexpected ISO14443AWrite return type: {type(raw_ret).__name__}, value={raw_ret!r}")
        # Conservatively assume success if it's even-weirdly truthy
        if raw_ret:
            return data_hex
        else:
            raise Exception(f"ISO14443AWrite failed with unrecognized return value: {raw_ret!r}")

    @log_elapsed
    def connect(self, ip_address: str, port: int) -> Tuple[int, int, str]:
        """
        Establishes a connection with the HFReader device. This method:
          - Opens the network port.
          - Retrieves reader information.
          - Enables the RF field and switches to ISO14443A mode.
          - Performs tag detection.
        Returns the UID as a hex string if detected.

        :param ip_address: The IP address of the reader.
        :param port: The network port number.
        :return:
        :raises RuntimeError: If the port cannot be opened after maximum retries.
        """
        log.info("Ensuring clean state before opening new connection...")
        uid_hex: str = None

        try:
            # Close any existing open port before a new connection
            if self.frm_handle:
                log.info(f"Closing existing network port {port} before opening a new one...")
                try:
                    self.close_net_port(self.frm_handle)
                    log.info(f" Successfully closed previous network port {port}.")
                except Exception as e:
                    log.warning(f" Warning: Failed to close previous network port {port}: {e}")

            # Proceed with normal connection flow
            # Open network port.
            log.info("STEP 1: Trying open_net_port...")
            com_addr, frm_handle = self.open_net_port(port, ip_address)
            log.info(f"com_addr: {com_addr}, frm_handle: {frm_handle}")
            log.info("STEP 1 OK")    

            # Open RF.
            log.info("STEP 2: Trying open_rf...")
            open_rf_result = self.open_rf(com_addr, frm_handle)
            log.info(f"open_rf_result: {open_rf_result}")
            log.info("STEP 2 OK")   

            # Change to ISO14443A.
            log.info("STEP 3: Trying change_to_14443A...")
            change_to_14443a_result = self.change_to_14443a(com_addr, frm_handle)
            log.info(f"change_to_14443a_result: {change_to_14443a_result}")
            log.info("STEP 3 OK")

            # ISO14443A Request.
            log.info("STEP 4: Trying iso14443a_request...")
            iso14443a_request_result = self.iso14443a_request(com_addr, 0, frm_handle)
            log.info(f"iso14443a_request_result: {iso14443a_request_result}")
            log.info("STEP 4 OK")

            # ISO14443A Anticoll.
            log.info("STEP 5: Trying iso14443a_anticoll...")
            uid_hex = self.iso14443a_anticoll(com_addr, frm_handle)
            log.info(f"uid_hex: {uid_hex}")
            log.info(f"STEP 5 OK: UID: {uid_hex}")

            # ISO14443A Select.
            log.info(f"STEP 6: trying select...")
            iso14443a_select_result = self.iso14443a_select(
                com_addr, uid_hex, frm_handle
            )
            log.info(f"iso14443a_select_result: {iso14443a_select_result}")
            log.info(f"STEP 6 OK.")

        except Exception as e:
            log.error(f"Connection error: {e}")

        return com_addr, frm_handle, uid_hex

    def disconnect(self):
        """
        Disconnects the reader by closing the network port.
        Enhanced logging and an optional delay are added to help diagnose issues.
        """
        log.info("Attempting to disconnect reader (close_net_port).")
        try:
            if self.frm_handle is None:
                log.warning("frm_handle is None; no active connection to disconnect.")
                return

            # Attempt to close the network port
            self.close_rf(self.com_addr, self.frm_handle)
            success = self.close_net_port(self.frm_handle)
            if success:
                log.info("Reader disconnected successfully.")
            else:
                log.error("Reader disconnect call returned failure.")

            # Optional: add a short delay to ensure the hardware fully releases the port
            # sleep(RETRY_DELAY)

        except Exception as e:
            log.error(f"Exception during disconnect: {e}")
            
    def open_sector(
        self,
        ip_address: str,
        port: int,
        sector: int,
        key_list: Optional[List[str]] = None,
    ) -> Tuple[Optional[int], Optional[int], Optional[str], bool, Optional[str]]:
        """
        Authenticates a specific card sector using multiple keys. This high-level function:
          - Validates provided keys.
          - Combines default keys with provided keys.
          - Iterates through each key, attempting authentication.
          - If a key fails, resets the connection before trying the next key.
        Returns a tuple containing the communication address, frame handle, UID, and a boolean indicating success.
 
        :param ip_address: The IP address of the reader.
        :param port: The network port number.
        :param sector: The sector number to authenticate.
        :param key_list: An optional list of hex key strings to try.
        :return: Tuple (com_addr, frm_handle, uid_hex, True) if authentication succeeds;
                 otherwise, (None, None, None, False).
        """
 
        # Prioridad: PRIMERO la ICKEY del hotel, DESPUÉS fallback a factory key
        if key_list and len(key_list) > 0:
            # Si hay keys, la primera es la ICKEY del hotel - probar PRIMERO
            hotel_key = key_list[0]
            other_keys = key_list[1:] if len(key_list) > 1 else []
            all_keys = [hotel_key] + other_keys + ["ffffffffffff"]
        else:
            # Si no hay keys, usar solo factory key
            all_keys = ["ffffffffffff"]
        all_keys_bytes = [bytes.fromhex(key) for key in all_keys]
 
        com_addr: Optional[int] = None
        frm_handle: Optional[int] = None
        uid_hex: Optional[str] = None
        auth_success: bool = False
 
        # Make sure to disconnect any existing connection first
        # self.disconnect()
 
        for key in all_keys_bytes:
            try:
                log.info(f"---------- Open sector {sector} with key {key}")
                log.info(f"Attempting authentication with key {key.hex()}...")
    
                # Connect. MID-LEVEL FUNCTION.
                com_addr, frm_handle, uid_hex = self.connect(ip_address, port)
                
                # Store the connection information in the instance
                self.com_addr = com_addr
                self.frm_handle = frm_handle
                self.uid_hex = uid_hex
    
                log.info(
                    f"reader.connect: com_addr: {com_addr}, frm_handle: {frm_handle}, uid_hex: {uid_hex}"
                )
    
                # ISO14443A AuthKey.
                iso14443a_auth_key_result = self.iso14443a_auth_key(
                    com_addr, 0, sector, key.hex(), frm_handle
                )
    
                if iso14443a_auth_key_result:
                    log.info(
                        f"Sector {sector}: Successfully authenticated with key {key.hex()}."
                    )
                    auth_success = True
                    return com_addr, frm_handle, uid_hex, True, key.hex()
                else:
                    log.warning(
                        f"Sector {sector}: Authentication failed with key {key.hex()}. Resetting connection..."
                    )
                    # time.sleep(RETRY_DELAY)
    
            except Exception as e:
                self.disconnect()
                log.warning(
                    f"Exception during authentication with key {key.hex()}: {e}"
                )
                continue
    
        log.error(f"Sector {sector}: Authentication failed with all keys.")
    
        return None, None, None, False, None

    # def open_sector(
    #     self,
    #     ip_address: str,
    #     port: int,
    #     sector: int,
    #     key_list: Optional[List[str]] = None,
    # ) -> Tuple[Optional[int], Optional[int], Optional[str], bool, Optional[str]]:
    #     """
    #     Authenticates a specific card sector using multiple keys. Prioritizes the hotel IC key first,
    #     then tries any provided keys, and finally falls back to FFFFFFFFFFFF.
    #     Returns (com_addr, frm_handle, uid_hex, auth_success, auth_key_hex).
    #     """

    #     # 🔐 ICKEY de hotel definida (ya debe estar almacenada en self.ic_key o algo similar)
    #     ic_key_str = getattr(self, "ic_key", None)
    #     if not ic_key_str:
    #         raise Exception("ICKEY is not set on this instance. Cannot proceed.")

    #     ic_key_str = ic_key_str.upper()
    #     key_list = key_list or []

    #     # 🔁 Limpia duplicados y ordena: ICKEY → otras → FFFF
    #     key_list_clean = [k.upper() for k in key_list if k.upper() != ic_key_str and k.upper() != "FFFFFFFFFFFF"]
    #     all_keys = [ic_key_str] + key_list_clean + ["FFFFFFFFFFFF"]
    #     all_keys_bytes = [bytes.fromhex(k) for k in all_keys]

    #     com_addr: Optional[int] = None
    #     frm_handle: Optional[int] = None
    #     uid_hex: Optional[str] = None
    #     auth_success: bool = False

    #     for key in all_keys_bytes:
    #         try:
    #             if LOG_INFO:
    #                 log.info(f"---------- Open sector {sector} with key {key}")
    #                 log.info(f"Attempting authentication with key {key.hex()}...")

    #             # 🧠 Connect (resetea DLL internamente)
    #             com_addr, frm_handle, uid_hex = self.connect(ip_address, port)

    #             self.com_addr = com_addr
    #             self.frm_handle = frm_handle
    #             self.uid_hex = uid_hex

    #             if LOG_INFO:
    #                 log.info(f"reader.connect: com_addr: {com_addr}, frm_handle: {frm_handle}, uid_hex: {uid_hex}")

    #             # 🗝️ Auth usando Key A (modo 0)
    #             iso14443a_auth_key_result = self.iso14443a_auth_key(
    #                 com_addr, 0, sector, key.hex(), frm_handle
    #             )

    #             if iso14443a_auth_key_result:
    #                 if LOG_INFO:
    #                     log.info(f"✅ Sector {sector}: Successfully authenticated with key {key.hex()}.")
    #                 return com_addr, frm_handle, uid_hex, True, key.hex()

    #             else:
    #                 if LOG_WARNING:
    #                     log.warning(f"❌ Sector {sector}: Auth failed with key {key.hex()}. Resetting connection...")

    #         except Exception as e:
    #             self.disconnect()
    #             if LOG_WARNING:
    #                 log.warning(f"⚠️ Exception during auth with key {key.hex()}: {e}")
    #             continue

    #     if LOG_ERROR:
    #         log.error(f"❌ Sector {sector}: Authentication failed with all keys.")

    #     return None, None, None, False, None

    def __enter__(self) -> "HFReaderDLLInterface":
        """
        Enters the runtime context related to this object.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        Exits the runtime context and disconnects the reader.
        """
        self.disconnect()