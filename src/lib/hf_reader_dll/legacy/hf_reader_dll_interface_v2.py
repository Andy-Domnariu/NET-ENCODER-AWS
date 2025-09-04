import sys, os, ctypes

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
from ctypes import c_long, c_ubyte, c_char_p, POINTER, byref, cast
from typing import Optional, Tuple, Dict, Any
from src.lib.utils.utils import Utils
from src.lib.utils.logger import Logger

log = Logger("hf_reader_dll_interface")


class HFReaderDLLInterface:
    """
    Interface for interacting with the Card Encoder DLL.
    This class loads the DLL and defines function signatures for various card operations.
    """

    # Grouped Error Codes
    GENERAL_ERRORS = {
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

    ISO14443A_ERRORS = {
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

    def __init__(
        self,
        dll_path: str = "dll\\HFReader.dll",
    ):
        """
        Initializes the DLL and configures its function signatures.

        :param dll_path: Path to the DLL file.
        """
        try:
            self.hf_reader_dll = ctypes.CDLL(dll_path)
        except Exception as e:
            log.error(f"Error loading DLL '{dll_path}': {e}")
            raise RuntimeError(f"Failed to load DLL: {dll_path}") from e

        self._define_function_signatures()

    def _define_function_signatures(self):
        """
        Configures each DLL function with appropriate argument and return types.
        """

        # Open a network port to connect to the reader.
        self.hf_reader_dll.OpenNetPort.argtypes = [
            c_long,  # Port: Network port number
            c_char_p,  # IPaddr: Pointer to a string containing the reader's IP address.
            POINTER(
                c_ubyte
            ),  # ComAddr: Pointer to the reader's communication address (input/output).
            POINTER(
                c_long
            ),  # FrmHandle: Pointer to the handle for the opened communication port.
        ]
        self.hf_reader_dll.OpenNetPort.restype = (
            c_long  # Returns 0 on success, other values indicate errors.
        )

        # Close the network port connected to the reader.
        self.hf_reader_dll.CloseNetPort.argtypes = [
            c_long
        ]  # FrmHandle: Handle of the communication port.
        self.hf_reader_dll.CloseNetPort.restype = c_long

        # Set the buzzer's action on the reader.
        self.hf_reader_dll.SetBeep.argtypes = [
            POINTER(c_ubyte),  # ComAddr: Pointer to the reader's communication address.
            c_ubyte,  # OpenTime: Buzzer activation duration (0-255, unit: 50ms).
            c_ubyte,  # CloseTime: Buzzer mute duration (0-255, unit: 50ms).
            c_ubyte,  # RepeatCount: Number of times to repeat the buzzer action.
            c_long,  # FrmHandle: Handle for the communication port.
        ]
        self.hf_reader_dll.SetBeep.restype = c_long

        # Enable the RF field.
        self.hf_reader_dll.OpenRf.argtypes = [
            POINTER(c_ubyte),  # ComAddr: Pointer to the reader's communication address.
            c_long,  # FrmHandle: Handle of the communication port.
        ]
        self.hf_reader_dll.OpenRf.restype = c_long
        # Disable the RF field.
        self.hf_reader_dll.CloseRf.argtypes = [
            POINTER(c_ubyte),  # ComAddr: Pointer to the reader's communication address.
            c_long,  # FrmHandle: Handle of the communication port.
        ]
        self.hf_reader_dll.CloseRf.restype = c_long

        # Switch the reader mode to ISO14443A.
        self.hf_reader_dll.ChangeTo14443A.argtypes = [
            POINTER(c_ubyte),  # ComAddr: Pointer to the reader's communication address.
            c_long,  # FrmHandle: Handle of the communication port.
        ]
        self.hf_reader_dll.ChangeTo14443A.restype = c_long

        # Request an ISO14443A tag in the RF field.
        self.hf_reader_dll.ISO14443ARequest.argtypes = [
            POINTER(c_ubyte),  # ComAddr: Pointer to the reader's communication address.
            c_ubyte,  # Mode: Request mode (0 = all tags except HALT, 1 = all tags).
            POINTER(
                c_ubyte
            ),  # TagType: Pointer to a 2-byte buffer storing the tag type (output).
            POINTER(
                c_ubyte
            ),  # ErrorCode: Pointer to a byte holding error details if function fails (output).
            c_long,  # FrmHandle: Handle of the communication port.
        ]
        self.hf_reader_dll.ISO14443ARequest.restype = c_long

        # Perform an anti-collision procedure to retrieve a tag's UID.
        self.hf_reader_dll.ISO14443AAnticoll.argtypes = [
            POINTER(c_ubyte),  # ComAddr: Pointer to the reader's communication address.
            c_ubyte,  # Reserved: Reserved for future use (default value: 0).
            POINTER(
                c_ubyte
            ),  # UID: Pointer to a 4-byte buffer for the tag's UID (output).
            POINTER(
                c_ubyte
            ),  # ErrorCode: Pointer to a byte holding error details if function fails (output).
            c_long,  # FrmHandle: Handle of the communication port.
        ]
        self.hf_reader_dll.ISO14443AAnticoll.restype = c_long

        # Select a tag in the RF field by its UID
        self.hf_reader_dll.ISO14443ASelect.argtypes = [
            POINTER(c_ubyte),  # ComAddr: Pointer to the reader's communication address.
            POINTER(c_ubyte),  # UID: Pointer to a 4-byte UID of the tag to select.
            POINTER(
                c_ubyte
            ),  # Size: Pointer to a byte storing the selected tag’s capacity (output).
            POINTER(
                c_ubyte
            ),  # ErrorCode: Pointer to a byte holding error details if function fails (output).
            c_long,  # FrmHandle: Handle of the communication port.
        ]
        self.hf_reader_dll.ISO14443ASelect.restype = c_long

        # Authenticate with the given key.
        self.hf_reader_dll.ISO14443AAuthKey.argtypes = [
            POINTER(c_ubyte),  # ComAddr: Pointer to the reader's communication address.
            c_ubyte,  # Mode: Authentication mode (0 = KEY A, 1 = KEY B).
            c_ubyte,  # AuthSector: Sector number to be authenticated.
            POINTER(c_ubyte),  # Key: Pointer to a 6-byte key for authentication.
            POINTER(
                c_ubyte
            ),  # ErrorCode: Pointer to a byte holding error details if function fails (output).
            c_long,  # FrmHandle: Handle of the communication port.
        ]
        self.hf_reader_dll.ISO14443AAuthKey.restype = c_long

        # --------------------------------------------------------------------------------

        # Read a memory block from the tag.
        self.hf_reader_dll.ISO14443ARead.argtypes = [
            POINTER(c_ubyte),  # ComAddr: Pointer to the reader's communication address.
            c_ubyte,  # BlockNum: Block number to read.
            POINTER(
                c_ubyte
            ),  # ReadData: Pointer to a buffer storing the 16-byte block data (output).
            POINTER(
                c_ubyte
            ),  # ErrorCode: Pointer to a byte holding error details if function fails (output).
            c_long,  # FrmHandle: Handle of the communication port.
        ]
        self.hf_reader_dll.ISO14443ARead.restype = c_long

        # Write data into one memory block.
        self.hf_reader_dll.ISO14443AWrite.argtypes = [
            POINTER(c_ubyte),  # ComAddr: Pointer to the reader's communication address.
            c_ubyte,  # BlockNum: Block number to write to.
            POINTER(
                c_ubyte
            ),  # WrittenData: Pointer to a 16-byte buffer containing the data to write.
            POINTER(
                c_ubyte
            ),  # ErrorCode: Pointer to a byte holding error details if function fails (output).
            c_long,  # FrmHandle: Handle of the communication port.
        ]
        self.hf_reader_dll.ISO14443AWrite.restype = c_long

        # Get general reader information.
        self.hf_reader_dll.GetReaderInformation.argtypes = [
            POINTER(c_ubyte),  # ComAddr: Pointer to the reader's communication address.
            POINTER(
                c_ubyte
            ),  # VersionInfo: Pointer to a 2-byte firmware version buffer (output).
            POINTER(
                c_ubyte
            ),  # ReaderType: Pointer to a byte storing the reader type (output).
            POINTER(
                c_ubyte
            ),  # TrType: Pointer to a 2-byte buffer for supported protocol types (output).
            POINTER(
                c_ubyte
            ),  # InventoryScanTime: Pointer to a byte storing the scan time setting (output).
            c_long,  # FrmHandle: Handle of the communication port.
        ]
        self.hf_reader_dll.GetReaderInformation.restype = c_long

    def _handle_result(
        self,
        function_name: str,
        result: int,
        error_group: Dict[int, str],
        success_msg: Optional[str] = None,
        raise_on_error: bool = True,
    ) -> int:
        """
        Handles and logs the result of a DLL function call.

        :param function_name: Name of the DLL function for logging.
        :param result: Return value from the DLL function.
        :param error_group: Dictionary containing the relevant error codes for this function.
        :param success_msg: Message to log if result == 0.
        :param raise_on_error: If True, raises an exception on error instead of just logging.
        :return: The same result code (so the caller can also handle it).
        :raises RuntimeError: If `raise_on_error` is True and the result indicates an error.
        """
        # log.debug(f"{function_name} returned status code: {result} (decimal: {result})")

        if result == 0:
            if success_msg:
                log.info(f"{function_name}: {success_msg}")
        else:
            error_msg = error_group.get(result, f"Unknown error code {result}")
            full_error_msg = f"{function_name} failed. {error_msg}."

            log.error(full_error_msg)

            if raise_on_error:
                raise RuntimeError(full_error_msg)

        return result

    def open_net_port(self, port: int, ip_address: str):
        """
        Opens a network port to connect to the HFReader device.
        """
        com_addr = c_ubyte(0)
        frm_handle = c_long()

        ip_bytes = ip_address.encode("utf-8")

        log.info(f"Attempting to open network port {port} at {ip_address}...")

        status = self.hf_reader_dll.OpenNetPort(
            c_long(port), c_char_p(ip_bytes), byref(com_addr), byref(frm_handle)
        )

        # log.info(f"OpenNetPort returned: {status} (decimal: {status})")
        # log.info(f"ComAddr: {com_addr.value}, FrmHandle: {frm_handle.value}")

        # Check if FrmHandle is -1, which indicates the network port did not open successfully.
        if frm_handle.value == -1:
            log.error("FrmHandle is -1. The network port did not open successfully.")

        self._handle_result(
            "OpenNetPort",
            status,
            self.GENERAL_ERRORS,
            "Network port opened successfully.",
        )

        return status, com_addr.value, frm_handle.value

    def close_net_port(self, frm_handle: int):
        """
        Closes the network port of the HFReader device.
        """
        log.info(f"Attempting to close network port with FrmHandle: {frm_handle}...")

        status = self.hf_reader_dll.CloseNetPort(c_long(frm_handle))

        self._handle_result(
            "CloseNetPort",
            status,
            self.GENERAL_ERRORS,
            "Network port closed successfully.",
        )

        return status

    def get_reader_information(self, com_addr: int, frm_handle: int):
        """
        Retrieves general reader information, such as firmware version and type.

        :param com_addr: Reader's communication address.
        :param frm_handle: Handle for the communication port.
        :return: Status code, dictionary with reader information, and error code.
        """
        com_addr_var = c_ubyte(com_addr)  # Convert com_addr to c_ubyte
        version_info = (c_ubyte * 2)()
        reader_type = c_ubyte(0)
        tr_type = (c_ubyte * 2)()
        scan_time = c_ubyte(0)
        error_code = c_ubyte(0)

        log.info("Retrieving reader information...")

        status = self.hf_reader_dll.GetReaderInformation(
            byref(com_addr_var),
            cast(version_info, POINTER(c_ubyte)),
            byref(reader_type),
            cast(tr_type, POINTER(c_ubyte)),
            byref(scan_time),
            c_long(frm_handle),
        )

        log.info(
            f"GetReaderInformation returned status: {status}, error code: {error_code.value}"
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

        if status == 0:
            log.info(f"Reader Information: {reader_info}")

        return status, reader_info, error_code.value

    def set_beep(
        self,
        com_addr: int,
        open_time: int,
        close_time: int,
        repeat_count: int,
        frm_handle: int,
    ):
        """
        Sets the buzzer action on the reader.
        """
        log.info(
            f"Setting beep with OpenTime: {open_time}, CloseTime: {close_time}, RepeatCount: {repeat_count}..."
        )

        status = self.hf_reader_dll.SetBeep(
            byref(c_ubyte(com_addr)),
            c_ubyte(open_time),
            c_ubyte(close_time),
            c_ubyte(repeat_count),
            c_long(frm_handle),
        )

        self._handle_result(
            "SetBeep",
            status,
            self.GENERAL_ERRORS,
            "Buzzer settings updated successfully.",
        )

        return status

    def open_rf(self, com_addr: int, frm_handle: int):
        """
        Enables the RF field of the reader.
        """
        log.info("Enabling RF field...")

        status = self.hf_reader_dll.OpenRf(
            byref(c_ubyte(com_addr)),
            c_long(frm_handle),
        )

        self._handle_result(
            "OpenRf",
            status,
            self.GENERAL_ERRORS,
            "RF field enabled successfully.",
        )

        return status

    def close_rf(self, com_addr: int, frm_handle: int):
        """
        Disables the RF field of the reader.
        """
        log.info("Disabling RF field...")

        status = self.hf_reader_dll.CloseRf(
            byref(c_ubyte(com_addr)),
            c_long(frm_handle),
        )

        self._handle_result(
            "CloseRf",
            status,
            self.GENERAL_ERRORS,
            "RF field disabled successfully.",
        )

        return status

    def change_to_14443a(self, com_addr: int, frm_handle: int):
        """
        Switches the reader mode to ISO14443A.
        """
        log.info("Changing reader mode to ISO14443A...")

        status = self.hf_reader_dll.ChangeTo14443A(
            byref(c_ubyte(com_addr)),
            c_long(frm_handle),
        )

        self._handle_result(
            "ChangeTo14443A",
            status,
            self.ISO14443A_ERRORS,
            "Reader mode switched to ISO14443A.",
        )

        return status

    def iso14443a_request(self, com_addr: int, mode: int, frm_handle: int):
        """
        Sends a request to detect an ISO14443A tag in the RF field.
        """
        com_addr_var = c_ubyte(com_addr)  # Store com_addr properly
        tag_type = (c_ubyte * 2)()  # Ensure correct buffer size
        error_code = c_ubyte(0)

        log.info(f"Requesting ISO14443A tag in RF field (Mode: {mode})...")
        log.info(f"Using ComAddr: {com_addr_var.value}, FrmHandle: {frm_handle}")

        status = self.hf_reader_dll.ISO14443ARequest(
            byref(com_addr_var),
            c_ubyte(mode),
            cast(tag_type, POINTER(c_ubyte)),
            byref(error_code),
            c_long(frm_handle),
        )

        log.info(
            f"ISO14443ARequest returned status: {status}, error code: {error_code.value}"
        )

        # Handle special case where no tag is detected
        if status == 5:
            log.warning(
                "No ISO14443A tag detected. Please place a tag near the reader."
            )
            return status, None, error_code.value

        self._handle_result(
            "ISO14443ARequest",
            status,
            self.ISO14443A_ERRORS,  # Use the correct error group
            "ISO14443A tag request completed.",
        )

        # Convert tag type to hex string correctly
        tag_type_str = f"{tag_type[1]:02X}{tag_type[0]:02X}" if status == 0 else None

        return status, tag_type_str, error_code.value

    def iso14443a_anticoll(self, com_addr: int, frm_handle: int):
        """
        Performs an anti-collision procedure to retrieve the tag’s UID.
        """
        reserved = c_ubyte(0)
        uid = (c_ubyte * 4)()
        error_code = c_ubyte(0)

        log.info("Performing ISO14443A anti-collision procedure...")
        log.info(f"Using ComAddr: {com_addr}, FrmHandle: {frm_handle}")

        status = self.hf_reader_dll.ISO14443AAnticoll(
            byref(c_ubyte(com_addr)),
            reserved,
            cast(uid, POINTER(c_ubyte)),
            byref(error_code),
            c_long(frm_handle),
        )

        log.info(
            f"ISO14443AAnticoll returned status: {status}, error code: {error_code.value}"
        )

        self._handle_result(
            "ISO14443AAnticoll",
            status,
            self.GENERAL_ERRORS,
            "ISO14443A anti-collision completed.",
        )

        uid_bytes = bytes(uid) if status == 0 else None
        uid_str = "".join(f"{byte:02X}" for byte in uid_bytes) if uid_bytes else None

        if uid_str:
            log.info(f"Detected UID: {uid_str}")

        return status, uid_bytes, error_code.value

    def iso14443a_select(self, com_addr: int, uid: bytes, frm_handle: int):
        """
        Selects an ISO14443A tag in the RF field by its UID.

        :param com_addr: Reader's communication address.
        :param uid: UID of the tag (must be 4 bytes).
        :param frm_handle: Handle for the communication port.
        :return: Status code, selected card size, and error code.
        """
        if len(uid) != 4:
            log.error("Invalid UID length. It must be exactly 4 bytes.")
            return -1, None, None

        com_addr_var = c_ubyte(com_addr)  # Store com_addr properly
        uid_array = (c_ubyte * 4)(*uid)  # Convert UID bytes to ctypes array
        size = c_ubyte(0)  # Store tag size
        error_code = c_ubyte(0)  # Store error code

        log.info(f"Selecting ISO14443A tag with UID: {uid.hex()}...")

        status = self.hf_reader_dll.ISO14443ASelect(
            byref(com_addr_var),
            uid_array,
            byref(size),
            byref(error_code),
            c_long(frm_handle),
        )

        log.info(
            f"ISO14443ASelect returned status: {status}, error code: {error_code.value}, Card Size: {size.value}"
        )

        self._handle_result(
            "ISO14443ASelect",
            status,
            self.ISO14443A_ERRORS,
            f"Tag successfully selected. Card size: {size.value}",
        )

        return status, size.value, error_code.value

    def iso14443a_auth_key(
        self, com_addr: int, mode: int, sector: int, key: bytes, frm_handle: int
    ):
        """
        Authenticates a sector on an ISO14443A card using a provided key.

        :param com_addr: Reader's communication address.
        :param mode: Authentication mode (0 = KEY A, 1 = KEY B).
        :param sector: Sector number to authenticate (0-15 for Mifare Classic).
        :param key: 6-byte authentication key.
        :param frm_handle: Handle for the communication port.
        :return: Status code and error code.
        """
        if len(key) != 6:
            log.error("Invalid key length. It must be exactly 6 bytes.")
            return -1, None

        com_addr_var = c_ubyte(com_addr)  # Convert com_addr to c_ubyte
        key_array = (c_ubyte * 6)(*key)  # Convert key to ctypes array
        error_code = c_ubyte(0)  # Store error code

        log.info(f"Authenticating sector {sector} using mode {mode}...")

        status = self.hf_reader_dll.ISO14443AAuthKey(
            byref(com_addr_var),
            c_ubyte(mode),
            c_ubyte(sector),
            key_array,
            byref(error_code),
            c_long(frm_handle),
        )

        log.info(
            f"ISO14443AAuthKey returned status: {status}, error code: {error_code.value}"
        )

        self._handle_result(
            "ISO14443AAuthKey",
            status,
            self.ISO14443A_ERRORS,
            f"Authentication successful for sector {sector}",
        )

        return status, error_code.value

    def iso14443a_read(self, com_addr: int, block_num: int, frm_handle: int):
        """
        Reads a 16-byte block from an ISO14443A tag.

        :param com_addr: Reader's communication address.
        :param block_num: Block number to read.
        :param frm_handle: Handle for the communication port.
        :return: Status code, read data (bytes), and error code.
        """
        com_addr_var = c_ubyte(com_addr)
        block_num_var = c_ubyte(block_num)
        read_data = (c_ubyte * 16)()
        error_code = c_ubyte(0)

        log.info(f"Reading block {block_num} from tag...")

        status = self.hf_reader_dll.ISO14443ARead(
            byref(com_addr_var),
            block_num_var,
            cast(read_data, POINTER(c_ubyte)),
            byref(error_code),
            c_long(frm_handle),
        )

        log.info(
            f"ISO14443ARead returned status: {status}, error code: {error_code.value}"
        )
        self._handle_result(
            "ISO14443ARead",
            status,
            self.ISO14443A_ERRORS,
            f"Block {block_num} read successfully." if status == 0 else None,
        )

        read_bytes = bytes(read_data) if status == 0 else None

        if read_bytes:
            log.info(f"Read Data: {read_bytes.hex()}")

        return status, read_bytes, error_code.value

    def iso14443a_write(
        self, com_addr: int, block_num: int, data: bytes, frm_handle: int
    ):
        """
        Writes a 16-byte block to an ISO14443A tag.

        :param com_addr: Reader's communication address.
        :param block_num: Block number to write to.
        :param data: 16-byte data to be written.
        :param frm_handle: Handle for the communication port.
        :return: Status code and error code.
        """
        if len(data) != 16:
            log.error("Invalid data length. It must be exactly 16 bytes.")
            return -1, None

        com_addr_var = c_ubyte(com_addr)
        block_num_var = c_ubyte(block_num)
        write_data = (c_ubyte * 16)(*data)
        error_code = c_ubyte(0)

        log.info(f"Writing to block {block_num} with data: {data.hex()}")

        status = self.hf_reader_dll.ISO14443AWrite(
            byref(com_addr_var),
            block_num_var,
            write_data,
            byref(error_code),
            c_long(frm_handle),
        )

        log.info(
            f"ISO14443AWrite returned status: {status}, error code: {error_code.value}"
        )

        self._handle_result(
            "ISO14443AWrite",
            status,
            self.ISO14443A_ERRORS,
            f"Block {block_num} written successfully." if status == 0 else None,
        )

        return status, error_code.value

    def prepare_reader(self, ip_address: str, port: int):
        """
        Prepares the HFReader device for operation.

        :param ip_address: The IP address of the reader.
        :param port: The network port to connect to the reader.
        :return: Tuple containing (reader instance, communication address, frame handle)
        """
        frm_handle_ref = None
        uid_hex = None

        try:
            status, com_addr, frm_handle = self.open_net_port(port, ip_address)

            if status == 0 and frm_handle != -1:
                frm_handle_ref = frm_handle
                reader_info_status, reader_info, reader_info_error = (
                    self.get_reader_information(com_addr, frm_handle)
                )
                self.open_rf(com_addr, frm_handle)
                change_to14443a_status = self.change_to_14443a(com_addr, frm_handle)
                if change_to14443a_status == 0:
                    request_status, tag_type, error_code = self.iso14443a_request(
                        com_addr, 0, frm_handle
                    )
                    if request_status == 0:
                        anticoll_status, uid, anticoll_error = self.iso14443a_anticoll(
                            com_addr, frm_handle
                        )
                        if anticoll_status == 0:
                            uid_hex = uid.hex()
                            select_status, card_size, select_error = (
                                self.iso14443a_select(com_addr, uid, frm_handle)
                            )
                            if select_status == 0:
                                key_a = bytes(
                                    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
                                )  # Default Mifare Classic key
                                auth_status, auth_error = self.iso14443a_auth_key(
                                    com_addr, 0, 1, key_a, frm_handle
                                )
                                if auth_status == 0:
                                    log.info("Authentication successful.")
                                    read_status, read_data, read_error = (
                                        self.iso14443a_read(com_addr, 4, frm_handle)
                                    )
                                    if read_status == 0:
                                        log.info(f"Read Data: {read_data.hex()}")

                return (
                    self,
                    com_addr,
                    frm_handle,
                    uid_hex,
                )  # Return initialized reader instance

        except RuntimeError as e:
            log.error(f"Exception occurred: {e}")
            if frm_handle_ref:
                self.close_rf(com_addr, frm_handle_ref)
                self.close_net_port(frm_handle_ref)
            raise

    def reset_connection(
        self, com_addr: int, frm_handle: int, ip_address: str, port: int
    ):
        """
        Resets the reader by closing the current connection and reinitializing it.

        :param reader: Instance of HFReaderDLLInterface.
        :param com_addr: Communication address of the current connection.
        :param frm_handle: Frame handle of the current connection.
        :param ip_address: IP address for the reader.
        :param port: Port for the reader.
        :return: Tuple (new_reader, new_com_addr, new_frm_handle) if reset succeeds, else None.
        """
        log.info("Attempting to reset reader connection...")

        try:
            # Step 1: Close the RF field and network port
            self.close_rf(com_addr, frm_handle)
            self.close_net_port(frm_handle)
            log.info("Successfully closed the current connection.")
        except Exception as e:
            log.error(f"Error closing the connection: {e}")
            return None, None, None

        try:
            # Step 2: Reinitialize the reader
            new_reader_instance, new_com_addr, new_frm_handle = self.prepare_reader(
                ip_address, port
            )
            log.info("Successfully reinitialized the reader.")
            return new_reader_instance, new_com_addr, new_frm_handle
        except Exception as e:
            log.error(f"Error reinitializing the reader: {e}")
            return None, None, None

    def close_connection(self, com_addr: int, frm_handle: int):
        """
        Safely closes the RF field and network port of the HFReader device.

        :param reader_instance: Instance of HFReaderDLLInterface.
        :param com_addr: Communication address of the reader.
        :param frm_handle: Frame handle of the communication port.
        """
        log.info("Closing reader connection...")

        try:
            self.close_rf(com_addr, frm_handle)
        except RuntimeError as e:
            log.warning(f"Failed to close RF field: {e}")

        try:
            self.close_net_port(frm_handle)
        except RuntimeError as e:
            log.warning(f"Failed to close network port: {e}")

        log.info("Reader connection closed.")


def main():
    """
    Main function to initialize the reader, authenticate, read data, write data, and handle failures.
    """
    ip_address = "88.30.56.6"
    port = 6000

    reader = HFReaderDLLInterface()

    try:
        # Step 1: Prepare the reader
        reader_instance, com_addr, frm_handle, uid_hex = reader.prepare_reader(
            ip_address, port
        )

        log.info("RESET -----------------")

        new_reader, new_com_addr, new_frm_handle = reader_instance.reset_connection(
            com_addr, frm_handle, ip_address, port
        )

        if new_reader:
            log.info("Reader successfully reset.")
            reader.close_connection(com_addr, frm_handle)
        else:
            log.error("Failed to reset the reader.")

        if reader_instance and False:  # Change to True to run the following steps.
            log.info(f"Reader successfully initialized. UID: {uid_hex}")

            # Step 2: Authenticate before reading/writing
            key_a = bytes(
                [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
            )  # Default Mifare Classic key
            sector = 1
            block = 4
            data_to_write = bytes(
                [
                    0x01,
                    0x02,
                    0x03,
                    0x04,
                    0x05,
                    0x06,
                    0x07,
                    0x08,
                    0x09,
                    0x0A,
                    0x0B,
                    0x0C,
                    0x0D,
                    0x0E,
                    0x0F,
                    0x10,
                ]
            )  # Example data

            auth_status, auth_error = reader_instance.iso14443a_auth_key(
                com_addr, 0, sector, key_a, frm_handle
            )
            if auth_status != 0:
                log.error(f"Authentication failed with error code: {auth_error}")
                raise RuntimeError("Authentication failed")

            log.info("Authentication successful.")

            # Step 3: Write to a block
            write_status, write_error = reader_instance.iso14443a_write(
                com_addr, block, data_to_write, frm_handle
            )
            if write_status == 0:
                log.info(f"Block {block} written successfully.")
            else:
                log.error(f"Failed to write block {block}. Error code: {write_error}")

            # Step 4: Read the block back to verify
            read_status, read_data, read_error = reader_instance.iso14443a_read(
                com_addr, block, frm_handle
            )
            if read_status == 0:
                log.info(f"Read Data from Block {block}: {read_data.hex()}")
            else:
                log.error(f"Failed to read block {block}. Error code: {read_error}")

    except RuntimeError as e:
        log.error(f"An error occurred: {e}")

        # Step 5: Reset connection if an error occurs
        log.info("Attempting to reset the connection...")
        new_reader, new_com_addr, new_frm_handle = reader_instance.reset_connection(
            com_addr, frm_handle, ip_address, port
        )

        if new_reader:
            log.info("Reader successfully reset.")
            reader.close_connection(com_addr, frm_handle)
        else:
            log.error("Failed to reset the reader.")

    finally:
        log.info("Closing reader connection...")
        reader.close_connection(com_addr, frm_handle)


if __name__ == "__main__":
    main()

""" 
FALTA AUTH!!!! auth_sector

Cambiar a open_connection el prepare_reader
 """
