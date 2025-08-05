import sys, os, ctypes
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
from ctypes import c_long, c_ubyte, c_char_p, POINTER, byref
from typing import Optional, Tuple, Dict, Any
from src.lib.utils.utils import Utils
from src.lib.utils.logger import Logger

log = Logger("hf_reader_dll_interface")

"""
Explanation of ctypes:
----------------------
The ctypes library in Python provides C compatible data types and allows calling functions
in DLLs or shared libraries. It can be used to wrap these libraries in pure Python.

- c_long, c_ubyte, c_char_p, POINTER, etc., are type definitions that match C data types.
- byref() is used to pass references of variables (similar to pointers in C).
- restype indicates the return type of the C function.
- argtypes is a tuple or list that specifies the argument types for the C function.
"""


class HFReaderDLLInterface:
    """
    A wrapper around a card reader DLL, providing higher-level methods
    to open/close a network port, perform RF field operations, and
    read/write blocks on an ISO14443A card, etc.
    """

    def __init__(self, dll_path="dll\\HFReader.dll"):
        """
        Initializes the class and loads the card reader DLL.

        Args:
            dll_path (str): Path to the card reader DLL file.

        Raises:
            RuntimeError: If the DLL fails to load.
        """
        try:
            self.hfreader = ctypes.WinDLL(dll_path)
        except Exception as e:
            log.error(f"Error loading DLL '{dll_path}': {e}")
            raise

        self._define_function_signatures()

    def _define_function_signatures(self):
        """
        Configures each DLL function with appropriate argument and return types.
        """

        self.hfreader.OpenNetPort.argtypes = [
            c_long,
            c_char_p,
            POINTER(c_ubyte),
            POINTER(c_long),
        ]
        self.hfreader.OpenNetPort.restype = c_long

        self.hfreader.SetBeep.argtypes = [
            POINTER(c_ubyte),
            c_ubyte,
            c_ubyte,
            c_ubyte,
            c_long,
        ]
        self.hfreader.SetBeep.restype = c_long

        self.hfreader.CloseNetPort.argtypes = [c_long]
        self.hfreader.CloseNetPort.restype = c_long

        self.hfreader.ISO14443AAnticoll.argtypes = [
            POINTER(c_ubyte),
            c_ubyte,
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_long,
        ]
        self.hfreader.ISO14443AAnticoll.restype = c_long

        self.hfreader.ISO14443ASelect.argtypes = [
            POINTER(c_ubyte),  # ComAddr
            POINTER(c_ubyte),  # UID
            POINTER(c_ubyte),  # Size
            POINTER(c_ubyte),  # ErrorCode
            c_long,  # FrmHandle
        ]
        self.hfreader.ISO14443ASelect.restype = c_long

        self.hfreader.ISO14443AAuthKey.argtypes = [
            POINTER(c_ubyte),  # ComAddr
            c_ubyte,  # Mode
            c_ubyte,  # AuthSector
            POINTER(c_ubyte),  # Key
            POINTER(c_ubyte),  # ErrorCode
            c_long,  # FrmHandle
        ]
        self.hfreader.ISO14443AAuthKey.restype = c_long

        self.hfreader.ISO14443ARead.argtypes = [
            POINTER(c_ubyte),  # ComAddr
            c_ubyte,  # BlockNum
            POINTER(c_ubyte),  # ReadData
            POINTER(c_ubyte),  # ErrorCode
            c_long,  # FrmHandle
        ]
        self.hfreader.ISO14443ARead.restype = c_long

        self.hfreader.ISO14443AWrite.argtypes = [
            POINTER(c_ubyte),  # ComAddr
            c_ubyte,  # BlockNum
            POINTER(c_ubyte),  # WrittenData
            POINTER(c_ubyte),  # ErrorCode
            c_long,  # FrmHandle
        ]
        self.hfreader.ISO14443AWrite.restype = c_long

        self.hfreader.GetReaderInformation.argtypes = [
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_long,
        ]
        self.hfreader.GetReaderInformation.restype = c_long

        self.hfreader.OpenRf.argtypes = [POINTER(c_ubyte), c_long]
        self.hfreader.OpenRf.restype = c_long

        self.hfreader.CloseRf.argtypes = [POINTER(c_ubyte), c_long]
        self.hfreader.CloseRf.restype = c_long

        self.hfreader.ChangeTo14443A.argtypes = [POINTER(c_ubyte), c_long]
        self.hfreader.ChangeTo14443A.restype = c_long

        self.hfreader.ISO14443ARequest.argtypes = [
            POINTER(c_ubyte),
            c_ubyte,
            POINTER(c_ubyte),
            POINTER(c_ubyte),
            c_long,
        ]
        self.hfreader.ISO14443ARequest.restype = c_long

    def _handle_result(
        self,
        function_name: str,
        result: int,
        error_code: Optional[int] = None,
        success_msg: Optional[str] = None,
    ) -> int:
        """
        Helper method to unify logging logic for result codes.

        Args:
            function_name (str): Name of the DLL function for logging.
            result (int): Return value from the DLL function.
            error_code (Optional[int]): If the DLL function provides an additional error code.
            success_msg (Optional[str]): The message to log if result == 0.

        Returns:
            int: The same result code (so the caller can also handle it).

        Note:
            - 0 typically indicates success.
            - 0x10 is frequently an "operation error" code in this particular library.
            - Other codes are handled as generic errors.
        """

        if result == 0:
            """if success_msg:
            Utils.log_message("SUCCESS", success_msg)"""
        """ elif result == 0x10:
            # Typically an operation error from this library
            if error_code is not None:
                Utils.log_message(
                    "ERROR",
                    f"{function_name} operation error. Error code: {error_code:02X}",
                )
            else:
                Utils.log_message("ERROR", f"{function_name} operation error. Code: {result}")
        else:
            Utils.log_message("ERROR", f"{function_name} returned error code {result}") """
        return result

    # ---------------------------------------------------------------------
    # Network / Connection
    # ---------------------------------------------------------------------


    def open_net_port_dll_wrapper(
        self, port: int, ip_address: str
    ) -> Tuple[Optional[c_ubyte], Optional[c_long]]:
        """
        Opens the network connection to the card reader.

        Args:
            port (int): Reader port.
            ip_address (str): Reader IP address.

        Returns:
            Tuple[Optional[c_ubyte], Optional[c_long]]:
                - com_addr (c_ubyte): The detected reader address (or None if failed).
                - frm_handle (c_long): The connection handle (or None if failed).
        """
        com_addr = c_ubyte(0xFF)  # Broadcast address
        frm_handle = c_long(0)

        try:
            result = self.hfreader.OpenNetPort(
                port, ip_address.encode(), byref(com_addr), byref(frm_handle)
            )
            if result == 0:
                # Utils.log_message("INFO", "Connection successfully established.")
                # Utils.log_message("INFO", f"Detected reader address: {com_addr.value}")
                # Utils.log_message("INFO", f"Returned handle: {frm_handle.value}")
                return com_addr, frm_handle
            else:
                Utils.log_message("ERROR", f"Error opening network port: Code {result}")
                return None, None
        except Exception as e:
            Utils.log_message("ERROR", f"Exception in OpenNetPort: {e}")
            return None, None

    def close_net_port_dll_wrapper(self, frm_handle: c_long) -> None:
        """
        Closes the connection to the card reader.

        Args:
            frm_handle (c_long): Connection handle.
        """
        try:
            result = self.hfreader.CloseNetPort(frm_handle.value)
            self._handle_result(
                "CloseNetPort", result, success_msg="Connection closed successfully."
            )
        except Exception as e:
            Utils.log_message("ERROR", f"Exception in CloseNetPort: {e}")
            
    # ---------------------------------------------------------------------
    # Reader (Beep, RF, etc.)
    # ---------------------------------------------------------------------

    def set_reader_beep_dll_wrapper(
        self,
        com_addr: c_ubyte,
        frm_handle: c_long,
        open_time: int,
        close_time: int,
        repeat_count: int,
    ) -> None:
        """
        Configures the reader's buzzer.

        Args:
            com_addr (c_ubyte): Reader address.
            frm_handle (c_long): Connection handle.
            open_time (int): The beep's ON duration.
            close_time (int): The beep's OFF duration.
            repeat_count (int): Number of beep repetitions.
        """
        try:
            result = self.hfreader.SetBeep(
                byref(com_addr), open_time, close_time, repeat_count, frm_handle.value
            )
            self._handle_result(
                "SetBeep", result, success_msg="Beep configured successfully."
            )
        except Exception as e:
            Utils.log_message("ERROR", f"Exception in SetBeep: {e}")

    def open_rf_field_dll_wrapper(self, com_addr: c_ubyte, frm_handle: c_long) -> int:
        """
        Turns on the RF field.

        Args:
            com_addr (c_ubyte): Reader address.
            frm_handle (c_long): Connection handle.

        Returns:
            int: The operation result (0 if successful).
        """
        try:
            result = self.hfreader.OpenRf(byref(com_addr), frm_handle.value)
            return self._handle_result(
                "OpenRf", result, success_msg="RF field turned on successfully."
            )
        except Exception as e:
            Utils.log_message("ERROR", f"Exception in OpenRf: {e}")
            return -1

    def close_rf_field_dll_wrapper(self, com_addr: c_ubyte, frm_handle: c_long) -> int:
        """
        Turns off the RF field.

        Args:
            com_addr (c_ubyte): Reader address.
            frm_handle (c_long): Connection handle.

        Returns:
            int: The operation result (0 if successful).
        """
        try:
            result = self.hfreader.CloseRf(byref(com_addr), frm_handle.value)
            return self._handle_result(
                "CloseRf", result, success_msg="RF field turned off successfully."
            )
        except Exception as e:
            Utils.log_message("ERROR", f"Exception in CloseRf: {e}")
            return -1

    def change_reader_mode_14443a_dll_wrapper(
        self, com_addr: c_ubyte, frm_handle: c_long
    ) -> int:
        """
        Changes the reader mode to ISO14443A.

        Args:
            com_addr (c_ubyte): Reader address.
            frm_handle (c_long): Connection handle.

        Returns:
            int: The operation result (0 if successful).
        """
        try:
            result = self.hfreader.ChangeTo14443A(byref(com_addr), frm_handle.value)
            return self._handle_result(
                "ChangeTo14443A",
                result,
                success_msg="Reader mode changed to ISO14443A successfully.",
            )
        except Exception as e:
            Utils.log_message("ERROR", f"Exception in ChangeTo14443A: {e}")
            return -1

    def get_reader_information_dll_wrapper(
        self, com_addr: c_ubyte, frm_handle: c_long
    ) -> Optional[Dict[str, Any]]:
        """
        Gets reader information such as firmware version, type, and supported protocol.

        Args:
            com_addr (c_ubyte): Reader address.
            frm_handle (c_long): Connection handle.

        Returns:
            Optional[Dict[str, Any]]:
                A dictionary with the reader information or None if it fails.
                Example structure:
                {
                    "version": "1.0",
                    "reader_type": 2,
                    "protocol": "0001",
                    "inventory_scan_time": 50
                }
        """
        version_info = (c_ubyte * 2)()
        reader_type = c_ubyte(0)
        tr_type = (c_ubyte * 2)()
        inventory_scan_time = c_ubyte(0)

        try:
            result = self.hfreader.GetReaderInformation(
                byref(com_addr),
                version_info,
                byref(reader_type),
                tr_type,
                byref(inventory_scan_time),
                frm_handle.value,
            )
            if result == 0:
                Utils.log_message("INFO", "Reader information obtained successfully.")
                reader_info = {
                    "version": f"{version_info[0]}.{version_info[1]}",
                    "reader_type": reader_type.value,
                    "protocol": f"{tr_type[0]:02X}{tr_type[1]:02X}",
                    "inventory_scan_time": inventory_scan_time.value,
                }
                Utils.log_message("INFO", f"Reader info: {reader_info}")
                return reader_info
            else:
                Utils.log_message("ERROR", f"GetReaderInformation error: Code {result}")
                return None
        except Exception as e:
            Utils.log_message("ERROR", f"Exception in GetReaderInformation: {e}")
            return None

    # ---------------------------------------------------------------------
    # Tag / Card Operations
    # ---------------------------------------------------------------------

    def detect_tags_in_rf_dll_wrapper(
        self, com_addr: c_ubyte, mode: int, frm_handle: c_long
    ) -> Optional[str]:
        """
        Detects ISO14443A tags in the RF field and returns the tag type if found.

        Args:
            com_addr (c_ubyte): Reader address.
            mode (int): Request mode (e.g., 0x00).
            frm_handle (c_long): Connection handle.

        Returns:
            Optional[str]: The detected tag type (hex string) or None if it fails.
        """
        tag_type = (c_ubyte * 2)()
        error_code = c_ubyte(0)

        try:
            result = self.hfreader.ISO14443ARequest(
                byref(com_addr), mode, tag_type, byref(error_code), frm_handle.value
            )
            # Use our helper to unify the log
            self._handle_result(
                "ISO14443ARequest",
                result,
                error_code=error_code.value,
                success_msg="ISO14443ARequest executed successfully.",
            )
            if result == 0:
                # Convert bytes to a hex string. Tag type often reversed
                tag_type_str = f"{tag_type[1]:02X}{tag_type[0]:02X}"
                # Utils.log_message("INFO", f"Detected tag type: {tag_type_str}")
                return tag_type_str
            return None
        except Exception as e:
            Utils.log_message("ERROR", f"Exception in ISO14443ARequest: {e}")
            return None

    def anticoll_unique_uid_dll_wrapper(
        self, com_addr: c_ubyte, frm_handle: c_long
    ) -> Optional[bytes]:
        """
        Performs anti-collision procedure and obtains the unique UID of a tag.

        Args:
            com_addr (c_ubyte): Reader address.
            frm_handle (c_long): Connection handle.

        Returns:
            Optional[bytes]: The tag's 4-byte UID or None if it fails.
        """
        reserved = c_ubyte(0)
        uid = (c_ubyte * 4)()
        error_code = c_ubyte(0)

        try:
            result = self.hfreader.ISO14443AAnticoll(
                byref(com_addr), reserved, uid, byref(error_code), frm_handle.value
            )
            self._handle_result(
                "ISO14443AAnticoll",
                result,
                error_code=error_code.value,
                success_msg="ISO14443AAnticoll executed successfully.",
            )
            if result == 0:
                uid_bytes = bytes(uid)
                uid_str = "".join(f"{byte:02X}" for byte in uid_bytes)
                # Utils.log_message("INFO", f"Detected UID: {uid_str}")
                return uid_bytes
            return None
        except Exception as e:
            Utils.log_message("ERROR", f"Exception in ISO14443AAnticoll: {e}")
            return None

    def select_tag_by_uid_dll_wrapper(
        self, com_addr: c_ubyte, uid: bytes, frm_handle: c_long
    ) -> Optional[int]:
        """
        Selects a specific tag in the RF field by its UID.

        Args:
            com_addr (c_ubyte): Reader address.
            uid (bytes): The card's UID (4 bytes).
            frm_handle (c_long): Connection handle.

        Returns:
            Optional[int]: The size of the selected card or None if it fails.
        """
        if len(uid) != 4:
            Utils.log_message("ERROR", "UID must be exactly 4 bytes.")
            return None

        uid_array = (c_ubyte * 4)(*uid)
        size = c_ubyte(0)
        error_code = c_ubyte(0)

        try:
            result = self.hfreader.ISO14443ASelect(
                byref(com_addr),
                uid_array,
                byref(size),
                byref(error_code),
                frm_handle.value,
            )
            self._handle_result(
                "ISO14443ASelect",
                result,
                error_code=error_code.value,
                success_msg="ISO14443ASelect executed successfully.",
            )
            if result == 0:
                # Utils.log_message("INFO", f"Selected card size: {size.value}")
                return size.value
            return None
        except Exception as e:
            Utils.log_message("ERROR", f"Exception in ISO14443ASelect: {e}")
            return None

    def auth_key_dll_wrapper(
        self,
        com_addr: c_ubyte,
        mode: int,
        sector_to_auth: int,
        key: bytes,
        frm_handle: c_long,
    ) -> int:
        """
        Authenticates using a provided key (6 bytes).

        Args:
            com_addr (c_ubyte): Reader address.
            mode (int): Authentication mode (0 for Key A, 1 for Key B).
            sector_to_auth (int): Sector to be authenticated.
            key (bytes): The authentication key (6 bytes).
            frm_handle (c_long): Connection handle.

        Returns:
            int: The operation result (0 if successful, otherwise an error code).
        """
        if len(key) != 6:
            Utils.log_message(
                "ERROR", f"Authentication key must be 6 bytes. Got {len(key)}."
            )
            return -1

        key_array = (c_ubyte * 6)(*key)
        error_code = c_ubyte(0)

        try:
            result = self.hfreader.ISO14443AAuthKey(
                byref(com_addr),
                c_ubyte(mode),
                c_ubyte(sector_to_auth),
                key_array,
                byref(error_code),
                frm_handle.value,
            )
            # Log it using our helper method
            return self._handle_result(
                "ISO14443AAuthKey", result, error_code=error_code.value
            )
        except Exception as e:
            Utils.log_message("ERROR", f"Exception in ISO14443AAuthKey: {e}")
            return -1

    def read_block_dll_wrapper(
        self, com_addr: c_ubyte, block_num: int, frm_handle: c_long
    ) -> Optional[bytes]:
        """
        Reads a memory block (16 bytes) from the tag.

        Args:
            com_addr (c_ubyte): Reader address.
            block_num (int): The block number to read.
            frm_handle (c_long): Connection handle.

        Returns:
            Optional[bytes]: The 16-byte data read or None if it fails.
        """
        read_data = (c_ubyte * 16)()
        error_code = c_ubyte(0)

        try:
            result = self.hfreader.ISO14443ARead(
                byref(com_addr),
                c_ubyte(block_num),
                read_data,
                byref(error_code),
                frm_handle.value,
            )
            self._handle_result("ISO14443ARead", result, error_code=error_code.value)
            if result == 0:
                return bytes(read_data)
            return None
        except Exception as e:
            Utils.log_message("ERROR", f"Exception in ISO14443ARead: {e}")
            return None

    def write_block_dll_wrapper(
        self, com_addr: c_ubyte, block_num: int, data: bytes, frm_handle: c_long
    ) -> int:
        """
        Writes data (16 bytes) to a memory block on the tag.

        Args:
            com_addr (c_ubyte): Reader address.
            block_num (int): The block number to write to.
            data (bytes): The data to write (must be exactly 16 bytes).
            frm_handle (c_long): Connection handle.

        Returns:
            int: The operation result (0 if successful, otherwise an error code).
        """
        if len(data) != 16:
            Utils.log_message("ERROR", f"Data must be 16 bytes long. Got {len(data)}.")
            return -1

        written_data = (c_ubyte * 16)(*data)
        error_code = c_ubyte(0)

        try:
            result = self.hfreader.ISO14443AWrite(
                byref(com_addr),
                c_ubyte(block_num),
                written_data,
                byref(error_code),
                frm_handle.value,
            )
            return self._handle_result(
                "ISO14443AWrite", result, error_code=error_code.value
            )
        except Exception as e:
            Utils.log_message("ERROR", f"Exception in ISO14443AWrite: {e}")
            return -1
