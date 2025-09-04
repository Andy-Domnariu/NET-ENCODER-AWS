import sys
import os
import ctypes
import time
from ctypes import c_long, c_ubyte, c_char_p, POINTER, byref, cast
from typing import Optional, Tuple, Dict, Any, List

# Allow relative imports.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from src.lib.utils.utils import Utils
from src.lib.utils.logger import Logger

log = Logger("hf_reader_dll_interface")

# Configurable constants.
RETRY_DELAY = 0  # seconds.
MAX_CONNECT_RETRIES = 2
LOG_INFO = False
LOG_WARNING = True
LOG_ERROR = True


class HFReaderDLLInterface:
    """
    Interface to interact with the HFReader via a DLL.
    This class loads the DLL, defines function signatures for card operations,
    and manages the connection via the 'connect' and 'disconnect' methods.
    """

    # Error codes for general operations.
    GENERAL_ERRORS: Dict[int, str] = {
        0: "OK",
        5: "Invalid command or request failed",
        48: "Communication error",
        49: "CRC verification error",
        50: "Data length error",
        51: "Communication busy",
        53: "Port is open",
        54: "Port is closed",
        55: "Invalid port handle",
        56: "Invalid port number",
        64: "Invalid key number",
        158: "Invalid parameter value",
        160: "AID not present in PICC",
        161: "Application encountered an unrecoverable error",
        190: "Read/write attempt outside file boundaries",
        193: "PICC encountered an unrecoverable error",
        240: "Specified file number does not exist",
        241: "File contains an unrecoverable error",
    }

    # Error codes for ISO14443A operations.
    ISO14443A_ERRORS: Dict[int, str] = {
        31: "Failed to halt",
        32: "No active ISO14443A tag in RF field",
        33: "Tag selection failed",
        34: "Authentication failed",
        35: "Read failed",
        36: "Write failed",
        37: "E-wallet initialization failed",
        38: "Value read failed",
        39: "Increment/Decrement failed",
        40: "Transfer failed",
        41: "EEPROM read/write failed",
        42: "Key load failed",
        43: "Write verification failed",
        44: "Write verification data error",
        45: "Value operation failed",
        46: "UltraLight write failed",
        48: "Anti-collision failed",
        49: "Multiple tags in RF field are not allowed",
        50: "Collision error between MifareOne and UltraLight",
        51: "Collision error in UltraLight tag",
    }

    def __init__(self, dll_path: str = "dll\\HFReader.dll") -> None:
        """
        Initialize the HFReaderDLLInterface instance by loading the DLL and
        initializing internal connection attributes.

        :param dll_path: Path to the HFReader DLL.
        :raises RuntimeError: If the DLL cannot be loaded.
        """
        try:
            self.hf_reader_dll = ctypes.CDLL(dll_path)
        except Exception as e:
            log.error(f"Error loading DLL '{dll_path}': {e}")
            raise RuntimeError(f"Failed to load DLL: {dll_path}") from e

        self.com_addr: Optional[int] = None
        self.frm_handle: Optional[int] = None
        self.uid_hex: Optional[str] = None

        self._define_function_signatures()

    def _define_function_signatures(self) -> None:
        """
        Define the argument and return types for each DLL function.
        """
        self.hf_reader_dll.OpenNetPort.argtypes = [
            c_long,
            c_char_p,
            POINTER(c_ubyte),
            POINTER(c_long),
        ]
        self.hf_reader_dll.OpenNetPort.restype = c_long

        self.hf_reader_dll.CloseNetPort.argtypes = [c_long]
        self.hf_reader_dll.CloseNetPort.restype = c_long

        self.hf_reader_dll.SetBeep.argtypes = [
            POINTER(c_ubyte),
            c_ubyte,
            c_ubyte,
            c_ubyte,
            c_long,
        ]
        self.hf_reader_dll.SetBeep.restype = c_long

        self.hf_reader_dll.OpenRf.argtypes = [POINTER(c_ubyte), c_long]
        self.hf_reader_dll.OpenRf.restype = c_long

        self.hf_reader_dll.CloseRf.argtypes = [POINTER(c_ubyte), c_long]
        self.hf_reader_dll.CloseRf.restype = c_long

        self.hf_reader_dll.ChangeTo14443A.argtypes = [POINTER(c_ubyte), c_long]
        self.hf_reader_dll.ChangeTo14443A.restype = c_long

        self.hf_reader_dll.ISO14443ARequest.argtypes = [
            POINTER(c_ubyte),
            c_ubyte,
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_long,
        ]
        self.hf_reader_dll.ISO14443ARequest.restype = c_long

        self.hf_reader_dll.ISO14443AAnticoll.argtypes = [
            POINTER(c_ubyte),
            c_ubyte,
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_long,
        ]
        self.hf_reader_dll.ISO14443AAnticoll.restype = c_long

        self.hf_reader_dll.ISO14443ASelect.argtypes = [
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_long,
        ]
        self.hf_reader_dll.ISO14443ASelect.restype = c_long

        self.hf_reader_dll.ISO14443AAuthKey.argtypes = [
            POINTER(c_ubyte),
            c_ubyte,
            c_ubyte,
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_long,
        ]
        self.hf_reader_dll.ISO14443AAuthKey.restype = c_long

        self.hf_reader_dll.ISO14443ARead.argtypes = [
            POINTER(c_ubyte),
            c_ubyte,
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_long,
        ]
        self.hf_reader_dll.ISO14443ARead.restype = c_long

        self.hf_reader_dll.ISO14443AWrite.argtypes = [
            POINTER(c_ubyte),
            c_ubyte,
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_long,
        ]
        self.hf_reader_dll.ISO14443AWrite.restype = c_long

        self.hf_reader_dll.GetReaderInformation.argtypes = [
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_long,
        ]
        self.hf_reader_dll.GetReaderInformation.restype = c_long

    def _handle_result(
        self,
        function_name: str,
        result: int,
        error_group: Dict[int, str],
        success_msg: Optional[str] = None,
        raise_on_error: bool = True,
        log_success: bool = False,
        log_error: bool = True,
    ) -> int:
        """
        Handle and log the result of a DLL call.

        :param function_name: The name of the DLL function.
        :param result: The result code from the function.
        :param error_group: Dictionary mapping error codes to messages.
        :param success_msg: Message to log on success.
        :param raise_on_error: Whether to raise a RuntimeError if result != 0.
        :return: The result code.
        :raises RuntimeError: If the result is non-zero and raise_on_error is True.
        """
        if result == 0:
            if success_msg and log_success:
                if LOG_INFO:
                    log.info(f"{function_name}: {success_msg}")
        else:
            error_msg = error_group.get(result, f"Unknown error code {result}")
            full_error_msg = f"{function_name} failed: {error_msg}."
            if log_error:
                log.error(full_error_msg)
            if raise_on_error:
                raise RuntimeError(full_error_msg)
        return result

    def open_net_port(self, port: int, ip_address: str) -> Tuple[int, int, int]:
        """
        Opens the network port to communicate with the reader.

        :param port: The network port number.
        :param ip_address: The IP address of the reader.
        :return: Tuple containing (status, communication address, frame handle).
        """
        com_addr = c_ubyte(0)
        frm_handle = c_long()
        ip_bytes = ip_address.encode("utf-8")

        if LOG_INFO:
            log.info(f"Opening network port {port} at {ip_address}...")

        status = self.hf_reader_dll.OpenNetPort(
            c_long(port), c_char_p(ip_bytes), byref(com_addr), byref(frm_handle)
        )

        self._handle_result(
            "OpenNetPort",
            status,
            self.GENERAL_ERRORS,
            "Network port opened successfully.",
        )
        return status, com_addr.value, frm_handle.value

    def close_net_port(self, frm_handle: int) -> int:
        """
        Closes the network port.

        :param frm_handle: The frame handle for the open port.
        :return: The status code from closing the port.
        """
        if LOG_INFO:
            log.info(f"Closing network port with frame handle {frm_handle}...")

        status = self.hf_reader_dll.CloseNetPort(c_long(frm_handle))

        self._handle_result(
            "CloseNetPort",
            status,
            self.GENERAL_ERRORS,
            "Network port closed successfully.",
        )

        return status

    def get_reader_information(
        self, com_addr: int, frm_handle: int
    ) -> Tuple[int, Dict[str, Any], int]:
        """
        Retrieves general information from the reader.

        :param com_addr: The communication address of the reader.
        :param frm_handle: The frame handle.
        :return: Tuple (status, reader_info dictionary, error code).
        """
        com_addr_var = c_ubyte(com_addr)
        version_info = (c_ubyte * 2)()
        reader_type = c_ubyte(0)
        tr_type = (c_ubyte * 2)()
        scan_time = c_ubyte(0)
        error_code = c_ubyte(0)

        if LOG_INFO:
            log.info("Retrieving reader information...")

        status = self.hf_reader_dll.GetReaderInformation(
            byref(com_addr_var),
            cast(version_info, POINTER(c_ubyte)),
            byref(reader_type),
            cast(tr_type, POINTER(c_ubyte)),
            byref(scan_time),
            c_long(frm_handle),
        )

        if LOG_INFO:
            log.info(
                f"GetReaderInformation status: {status}, error code: {error_code.value}"
            )

        self._handle_result(
            "GetReaderInformation",
            status,
            self.GENERAL_ERRORS,
            "Reader information retrieved successfully.",
        )

        reader_info = {
            "firmware_version": f"{version_info[1]:02X}.{version_info[0]:02X}",
            "reader_type": reader_type.value,
            "supported_protocols": f"{tr_type[1]:02X}{tr_type[0]:02X}",
            "scan_time": scan_time.value,
        }
        if LOG_INFO:
            log.info(
                f"Reader Information: {reader_info}"
                if status == 0
                else "Failed to retrieve reader information."
            )

        return status, reader_info, error_code.value

    def open_rf(self, com_addr: int, frm_handle: int) -> int:
        """
        Enables the RF field of the reader.

        :param com_addr: The communication address.
        :param frm_handle: The frame handle.
        :return: The status code from enabling the RF field.
        """
        if LOG_INFO:
            log.info("Enabling RF field...")

        status = self.hf_reader_dll.OpenRf(byref(c_ubyte(com_addr)), c_long(frm_handle))

        self._handle_result(
            "OpenRf", status, self.GENERAL_ERRORS, "RF field enabled successfully."
        )

        return status

    def close_rf(self, com_addr: int, frm_handle: int) -> int:
        """
        Disables the RF field of the reader.

        :param com_addr: The communication address.
        :param frm_handle: The frame handle.
        :return: The status code from disabling the RF field.
        """
        if LOG_INFO:
            log.info("Disabling RF field...")

        status = self.hf_reader_dll.CloseRf(
            byref(c_ubyte(com_addr)), c_long(frm_handle)
        )

        self._handle_result(
            "CloseRf", status, self.GENERAL_ERRORS, "RF field disabled successfully."
        )

        return status

    def change_to_14443a(self, com_addr: int, frm_handle: int) -> int:
        """
        Switches the reader mode to ISO14443A.

        :param com_addr: The communication address.
        :param frm_handle: The frame handle.
        :return: The status code from changing the mode.
        """
        if LOG_INFO:
            log.info("Switching reader mode to ISO14443A...")

        status = self.hf_reader_dll.ChangeTo14443A(
            byref(c_ubyte(com_addr)), c_long(frm_handle)
        )

        self._handle_result(
            "ChangeTo14443A",
            status,
            self.ISO14443A_ERRORS,
            "Reader mode set to ISO14443A.",
        )

        return status

    def iso14443a_request(
        self, com_addr: int, mode: int, frm_handle: int
    ) -> Tuple[int, Optional[str], int]:
        """
        Sends a request to detect an ISO14443A tag.

        :param com_addr: The communication address.
        :param mode: The request mode (0 or 1).
        :param frm_handle: The frame handle.
        :return: Tuple (status, tag type as hex string if detected, error code).
        """
        com_addr_var = c_ubyte(com_addr)
        tag_type = (c_ubyte * 2)()
        error_code = c_ubyte(0)

        if LOG_INFO:
            log.info(f"Requesting ISO14443A tag (mode={mode})...")

        status = self.hf_reader_dll.ISO14443ARequest(
            byref(com_addr_var),
            c_ubyte(mode),
            cast(tag_type, POINTER(c_ubyte)),
            byref(error_code),
            c_long(frm_handle),
        )

        if LOG_INFO:
            log.info(
                f"ISO14443ARequest status: {status}, error code: {error_code.value}"
            )

        if status == 5:
            if LOG_WARNING:
                log.warning("No ISO14443A tag detected.")
            return status, None, error_code.value

        self._handle_result(
            "ISO14443ARequest",
            error_code.value,
            self.ISO14443A_ERRORS,
            "ISO14443A tag request completed.",
        )

        tag_type_str = f"{tag_type[1]:02X}{tag_type[0]:02X}" if status == 0 else None

        return status, tag_type_str, error_code.value

    def iso14443a_anticoll(
        self, com_addr: int, frm_handle: int
    ) -> Tuple[int, Optional[bytes], int]:
        """
        Performs an anti-collision procedure to retrieve the tag UID.

        :param com_addr: The communication address.
        :param frm_handle: The frame handle.
        :return: Tuple (status, UID as bytes if detected, error code).
        """
        reserved = c_ubyte(0)
        uid = (c_ubyte * 4)()
        error_code = c_ubyte(0)

        if LOG_INFO:
            log.info("Performing anti-collision...")

        status = self.hf_reader_dll.ISO14443AAnticoll(
            byref(c_ubyte(com_addr)),
            reserved,
            cast(uid, POINTER(c_ubyte)),
            byref(error_code),
            c_long(frm_handle),
        )

        if LOG_INFO:
            log.info(
                f"ISO14443AAnticoll status: {status}, error code: {error_code.value}"
            )

        self._handle_result(
            "ISO14443AAnticoll",
            error_code.value,
            self.ISO14443A_ERRORS,
            "Anti-collision completed.",
        )

        uid_bytes = bytes(uid) if status == 0 else None

        if uid_bytes:
            if LOG_INFO:
                log.info(f"Detected UID: {''.join(f'{b:02X}' for b in uid_bytes)}")

        return status, uid_bytes, error_code.value

    def iso14443a_select(
        self, com_addr: int, uid: bytes, frm_handle: int
    ) -> Tuple[int, Optional[int], int]:
        """
        Selects an ISO14443A tag using its UID.

        :param com_addr: The communication address.
        :param uid: The UID of the tag (must be 4 bytes).
        :param frm_handle: The frame handle.
        :return: Tuple (status, card size if selected, error code).
        """
        if len(uid) != 4:
            log.error("Invalid UID length. Must be 4 bytes.")
            return -1, None, None
        com_addr_var = c_ubyte(com_addr)
        uid_array = (c_ubyte * 4)(*uid)
        size = c_ubyte(0)
        error_code = c_ubyte(0)
        # log.info(f"Selecting tag with UID: {uid.hex()}...")
        status = self.hf_reader_dll.ISO14443ASelect(
            byref(com_addr_var),
            uid_array,
            byref(size),
            byref(error_code),
            c_long(frm_handle),
        )
        # log.info(
        #     f"ISO14443ASelect status: {status}, card size: {size.value}, error code: {error_code.value}"
        # )
        self._handle_result(
            "ISO14443ASelect",
            status,
            self.ISO14443A_ERRORS,
            f"Tag selected. Card size: {size.value}",
        )
        return status, size.value, error_code.value

    def iso14443a_auth_key(
        self, com_addr: int, mode: int, sector: int, key: bytes, frm_handle: int
    ) -> Tuple[int, int]:
        """
        Authenticates a card sector using a 6-byte key.

        :param com_addr: The communication address.
        :param mode: Authentication mode (0 for Key A, 1 for Key B).
        :param sector: The sector number to authenticate.
        :param key: The 6-byte key as bytes.
        :param frm_handle: The frame handle.
        :return: Tuple (status, error code).
        """
        if len(key) != 6:
            log.error("Invalid key length. Must be 6 bytes.")
            return -1, None

        com_addr_var = c_ubyte(com_addr)
        key_array = (c_ubyte * 6)(*key)
        error_code = c_ubyte(0)

        if LOG_INFO:
            log.info(
                f"Authenticating sector {sector} with mode {mode} using key {key.hex()}..."
            )

        status = self.hf_reader_dll.ISO14443AAuthKey(
            byref(com_addr_var),
            c_ubyte(mode),
            c_ubyte(sector),
            key_array,
            byref(error_code),
            c_long(frm_handle),
        )

        if LOG_INFO:
            log.info(
                f"ISO14443AAuthKey status: {status}, error code: {error_code.value}"
            )

        self._handle_result(
            "ISO14443AAuthKey",
            error_code.value,
            self.ISO14443A_ERRORS,
            f"Authentication successful for sector {sector}.",
        )

        return status, error_code.value

    def iso14443a_read(
        self, com_addr: int, block_num: int, frm_handle: int
    ) -> Tuple[int, Optional[bytes], int]:
        """
        Reads a 16-byte block of data from the tag.

        :param com_addr: The communication address.
        :param block_num: The block number to read.
        :param frm_handle: The frame handle.
        :return: Tuple (status, data bytes if read successfully, error code).
        """
        com_addr_var = c_ubyte(com_addr)
        block_num_var = c_ubyte(block_num)
        read_data = (c_ubyte * 16)()
        error_code = c_ubyte(0)

        if LOG_INFO:
            log.info(f"Reading block {block_num}...")

        status = self.hf_reader_dll.ISO14443ARead(
            byref(com_addr_var),
            block_num_var,
            cast(read_data, POINTER(c_ubyte)),
            byref(error_code),
            c_long(frm_handle),
        )

        if LOG_INFO:
            log.info(f"ISO14443ARead status: {status}, error code: {error_code.value}")

        self._handle_result(
            "ISO14443ARead",
            error_code.value,
            self.ISO14443A_ERRORS,
            f"Block {block_num} read successfully." if status == 0 else None,
        )

        data_bytes = bytes(read_data) if status == 0 else None

        if data_bytes:
            if LOG_INFO:
                log.info(f"Data read: {data_bytes.hex()}")

        return status, data_bytes, error_code.value

    def iso14443a_write(
        self, com_addr: int, block_num: int, data: bytes, frm_handle: int
    ) -> Tuple[int, int]:
        """
        Writes a 16-byte block of data to the tag.

        :param com_addr: The communication address.
        :param block_num: The block number to write.
        :param data: The 16-byte data as bytes.
        :param frm_handle: The frame handle.
        :return: Tuple (status, error code).
        """
        if len(data) != 16:
            log.error("Invalid data length. Must be 16 bytes.")
            return -1, None

        com_addr_var = c_ubyte(com_addr)
        block_num_var = c_ubyte(block_num)
        write_data = (c_ubyte * 16)(*data)
        error_code = c_ubyte(0)

        if LOG_INFO:
            log.info(f"Writing to block {block_num} with data: {data.hex()}...")

        status = self.hf_reader_dll.ISO14443AWrite(
            byref(com_addr_var),
            block_num_var,
            write_data,
            byref(error_code),
            c_long(frm_handle),
        )

        if LOG_INFO:
            log.info(f"ISO14443AWrite status: {status}, error code: {error_code.value}")

        self._handle_result(
            "ISO14443AWrite",
            error_code.value,
            self.ISO14443A_ERRORS,
            f"Block {block_num} written successfully." if status == 0 else None,
        )

        return status, error_code.value

    def connect(self, ip_address: str, port: int) -> Optional[str]:
        """
        Establishes a connection with the HFReader device. This method:
          - Opens the network port.
          - Retrieves reader information.
          - Enables the RF field and switches to ISO14443A mode.
          - Performs tag detection.
        Returns the UID as a hex string if detected.

        :param ip_address: The IP address of the reader.
        :param port: The network port number.
        :return: UID as a hex string if connection and tag detection are successful; otherwise, None.
        :raises RuntimeError: If the port cannot be opened after maximum retries.
        """
        retries = 0
        while retries < MAX_CONNECT_RETRIES:
            try:
                status, com_addr, frm_handle = self.open_net_port(port, ip_address)
                break
            except RuntimeError as e:
                if "Port is open" in str(e):
                    if LOG_WARNING:
                        log.warning("Port is open; attempting disconnect and retry.")
                    self.disconnect()
                    # time.sleep(RETRY_DELAY)
                    retries += 1
                else:
                    raise
        else:
            raise RuntimeError("Exceeded maximum retries to open network port.")

        if status != 0 or frm_handle == -1:
            raise RuntimeError("Failed to open network port.")

        self.com_addr = com_addr
        self.frm_handle = frm_handle

        self.get_reader_information(com_addr, frm_handle)
        self.open_rf(com_addr, frm_handle)

        if self.change_to_14443a(com_addr, frm_handle) == 0:
            req_status, tag_type, _ = self.iso14443a_request(com_addr, 0, frm_handle)
            if req_status == 0:
                anticoll_status, uid, _ = self.iso14443a_anticoll(com_addr, frm_handle)
                if anticoll_status == 0 and uid:
                    self.uid_hex = uid.hex()
                    sel_status, _, _ = self.iso14443a_select(com_addr, uid, frm_handle)
                    if sel_status == 0:
                        if LOG_INFO:
                            log.info(f"Connected to reader with UID: {self.uid_hex}")
                else:
                    if LOG_WARNING:
                        log.warning("Anti-collision did not detect a valid UID.")
            else:
                if LOG_WARNING:
                    log.warning("ISO14443A tag request did not detect any tag.")
        return self.uid_hex

    def disconnect(self) -> None:
        """
        Closes the connection by disabling the RF field and closing the network port.
        """
        if self.com_addr is not None and self.frm_handle is not None:
            try:
                self.close_rf(self.com_addr, self.frm_handle)
            except RuntimeError as e:
                if LOG_WARNING:
                    log.warning(f"Error closing RF field: {e}")
            try:
                self.close_net_port(self.frm_handle)
            except RuntimeError as e:
                if LOG_WARNING:
                    log.warning(f"Error closing network port: {e}")
            self.com_addr = None
            self.frm_handle = None
            self.uid_hex = None
            # log.info("Disconnected from reader.")

    def open_sector(
        self,
        ip_address: str,
        port: int,
        sector: int,
        key_list: Optional[List[str]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Authenticates a specific card sector using multiple keys. This high-level function:
          - Validates provided keys.
          - Combines default keys with provided keys.
          - Iterates through each key, attempting authentication.
          - If a key fails, resets the connection before trying the next key.
        Returns a tuple indicating success and the UID if successful.

        :param ip_address: The IP address of the reader.
        :param port: The network port number.
        :param sector: The sector number to authenticate.
        :param key_list: An optional list of hex key strings to try.
        :return: Tuple (True, UID) if authentication succeeds; otherwise, (False, None).
        """
        if key_list and not all(Utils.is_hexadecimal(key) for key in key_list):
            log.error("Invalid hexadecimal key(s) in the list.")
            return False, None

        # Default keys: try "FFFFFFFFFFFA" first (expected to fail) then "FFFFFFFFFFFF" (expected to succeed)
        all_keys = ["FFFFFFFFFFFA", "FFFFFFFFFFFF"] + (key_list or [])
        all_keys_bytes = [bytes.fromhex(key) for key in all_keys]

        for key in all_keys_bytes:
            try:
                if LOG_INFO:
                    log.info(
                        "-------------------------------------------------------------"
                    )
                    log.info(f"Attempting authentication with key {key.hex()}...")

                new_uid = self.connect(ip_address, port)
                if new_uid is None:
                    log.error("Connection failed during authentication attempt.")
                    return False, None

                result, _ = self.iso14443a_auth_key(
                    self.com_addr, 0, sector, key, self.frm_handle
                )
                if result == 0:
                    if LOG_INFO:
                        log.info(
                            f"Sector {sector}: Successfully authenticated with key {key.hex()}."
                        )
                    return True, self.uid_hex
                else:
                    if LOG_WARNING:
                        log.warning(
                            f"Sector {sector}: Authentication failed with key {key.hex()}. Resetting connection..."
                        )
                    self.disconnect()
                    # time.sleep(RETRY_DELAY)
                    new_uid = self.connect(ip_address, port)
                    if self.com_addr is None or self.frm_handle is None:
                        log.error("Failed to reset connection. Exiting authentication.")
                        return False, None
            except Exception as e:
                # log.error(f"Exception during authentication with key {key.hex()}: {e}")
                continue

        log.error(f"Sector {sector}: Authentication failed with all keys.")
        return False, None

    def __enter__(self) -> "HFReaderDLLInterface":
        """
        Enter the runtime context related to this object.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """
        Exit the runtime context and disconnect the reader.
        """
        self.disconnect()


def main() -> None:
    """
    Main function demonstrating usage of HFReaderDLLInterface:
      - Authenticates a specific sector using default keys.
      - Reads a block (block 4) from the authenticated sector.
      - Writes data to the same block.
    """
    ip_address = "88.30.56.6"
    port = 6000
    sector = 1
    block = 4
    write_data = bytes.fromhex("112233445566778899AABBCCDDEEFF00")

    reader = HFReaderDLLInterface()
    try:
        result, uid = reader.open_sector(ip_address, port, sector, key_list=None)
        log.info(f"Open_sector for sector {sector} result: {result} with UID: {uid}")

        if result and uid:
            # Read data from block 4.
            read_status, data, _ = reader.iso14443a_read(
                reader.com_addr, block, reader.frm_handle
            )

            if read_status != 0:
                log.error(f"Read failed for block {block}.")
                return

            log.info(
                f"Read status: {read_status}, block: {block}, data: {data.hex() if data else None}"
            )

            # Write data to block 4.
            write_status, _ = reader.iso14443a_write(
                reader.com_addr, block, write_data, reader.frm_handle
            )

            if write_status != 0:
                log.error(f"Write failed for block {block}.")
                return

            log.info(
                f"Write status: {write_status}, block: {block}, data: {write_data.hex()}"
            )

            # Read data from block 4. Again.
            read_status, data, _ = reader.iso14443a_read(
                reader.com_addr, block, reader.frm_handle
            )

            if read_status != 0:
                log.error(f"Read failed for block {block}.")
                return

            log.info(
                f"Read status: {read_status}, block: {block}, data: {data.hex() if data else None}"
            )
    except RuntimeError as e:
        log.error(f"Connection error: {e}")
    finally:
        reader.disconnect()


if __name__ == "__main__":
    main()
