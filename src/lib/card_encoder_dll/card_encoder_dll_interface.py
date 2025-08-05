import sys, os, ctypes, requests
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
from typing import Optional, List
from src.lib.utils.logger import Logger
from src.lib.card_encoder_dll.card_encoder_dll_utils import CardEncoderDllUtils
log = Logger("card_encoder_dll_interface")


class CardEncoderDLLInterface:
    """
    Interface for interacting with the Card Encoder DLL.
    This class loads the DLL and defines function signatures for various card operations.
    """

    ERROR_CODES = {
        0: "OK",
        1: "Operation failed",
        2: "Parameter error",
        3: "Communication error (command sending error)",
        4: "Communication error (command reading error, please re-plug)",
        5: "Communication error (command error)",
        6: "Key not set",
        7: "Operation failed, card issuance mode not entered",
        8: "Operation interruption failed (failed when stopping the operation of sending a blank card)",
        9: "Operation interrupted (stop sending blank card operation, original operation returns)",
        10: "Server address is not configured",
        11: "Network request failed. Please check your internet connection.",
        12: "Data returned by the interface does not meet format requirements. Please reconfigure the server.",
        13: "hotelInfo is invalid",
        14: "Not this hotel's card reader",
        15: "The card issuer is not initialized",
        16: "The device is not connected and cannot be operated",
        28: "Failed to configure the serial port",
        31: "Unable to open log file",
        32: "The card issuer does not support this command operation, please upgrade the hardware version",
        33: "The card issuer does not support CPU card operation",
        34: "Cycle mode not currently supported",
        35: "Sector out of bounds",
        36: "Inoperable sectors",
        37: "Sector data is incomplete",
        38: "The serial port is not connected to a device",
        39: "The serial port is already occupied",
        40: "The device has been disconnected",
        41: "The path could not be resolved or the file could not be opened",
        42: "Path is empty",
        43: "The path format is incorrect",
        47: "The number of failed read data has exceeded, read data timed out, communication failed",
        48: "Invalid server address",
        49: "Response frame error, cannot be parsed normally",
        50: "Data frame cyclic checksum error",
        301: "Other errors in data parsing",
        301: "Other errors in data parsing",
        304: "Insufficient sector space",
        305: "Key decryption failed or not configured",
        307: "IC card data does not exist",
        308: "Need to operate the next sector (new in 1.6.0 , third-party V2)",
        309: "Parameter exception (new in 1.6.0 )",
        310: "Retrieve sector data anomaly (new in 1.6.0 , third-party V2 )",
        420: "Data not returned normally",
    }

    def __init__(self, dll_path: str = "dll\\CardEncoder.dll"):
        """
        Initializes the DLL and configures its function signatures.

        :param dll_path: Path to the DLL file.
        :param server_ip: Optional IP address of the remote server.
        :param server_port: Optional port number of the remote server.
        """
        try:
            self.card_encoder_dll = ctypes.CDLL(dll_path)
        except Exception as e:
            
            log.error(f"Error loading DLL '{dll_path}': {e}")
            raise RuntimeError(f"Failed to load DLL: {dll_path}") from e

        self._define_function_signatures()

    def _define_function_signatures(self) -> None:
        """
        Defines function signatures for the DLL functions, specifying argument and return types.
        """
        # ConfigServer.
        self.card_encoder_dll.CE_ConfigServer.argtypes = [ctypes.c_char_p]
        self.card_encoder_dll.CE_ConfigServer.restype = ctypes.c_int

        # GenerateSectorData.
        self.card_encoder_dll.CE_GenerateSectorData.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_bool,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_ulong,
            ctypes.c_bool,
        ]
        self.card_encoder_dll.CE_GenerateSectorData.restype = ctypes.c_int

        # Server GenerateSectorData
        self.card_encoder_dll.CE_GenerateSectorData_Server.argtypes = [
            ctypes.c_char_p,  # hotelInfo
            ctypes.c_char_p,  # sectorData
            ctypes.c_ubyte,  # isLowestSector
            ctypes.c_int,  # buildNo
            ctypes.c_int,  # floorNo
            ctypes.c_char_p,  # mac
            ctypes.c_char_p,  # timeStr
            ctypes.c_ubyte,  # allowLockOut
        ]
        self.card_encoder_dll.CE_GenerateSectorData_Server.restype = ctypes.c_int

        # CancelCard
        self.card_encoder_dll.CE_CancelCard.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ubyte),
        ]
        self.card_encoder_dll.CE_CancelCard.restype = ctypes.c_int

        # InitCard
        self.card_encoder_dll.CE_InitCard.argtypes = [ctypes.c_char_p]
        self.card_encoder_dll.CE_InitCard.restype = ctypes.c_int

        # ClearCard
        self.card_encoder_dll.CE_ClearCard.argtypes = [ctypes.c_char_p]
        self.card_encoder_dll.CE_ClearCard.restype = ctypes.c_int

        # GenerateCancelCardData
        self.card_encoder_dll.CE_GenerateCancelCardData.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_bool,
            ctypes.c_char_p,
            ctypes.c_ulong,
        ]
        self.card_encoder_dll.CE_GenerateCancelCardData.restype = ctypes.c_int

        # Server GenerateCancelCardData
        self.card_encoder_dll.CE_GenerateCancelCardData_Server.argtypes = [
            ctypes.c_char_p,  # hotelInfo
            ctypes.c_char_p,  # sectorData
            ctypes.c_ubyte,  # isLowestSector
            ctypes.c_char_p,  # uid
            ctypes.c_char_p,  # timeStr
        ]
        self.card_encoder_dll.CE_GenerateCancelCardData_Server.restype = ctypes.c_int

    def _handle_result(
        self, function_name: str, result: int, error_code: Optional[int] = None
    ) -> None:
        """
        Handles and logs the result of a DLL function call.

        :param function_name: Name of the DLL function for logging.
        :param result: Return value from the DLL function.
        :param error_code: Error code from the DLL function.
        :return: The same result code (so the caller can also handle it).
        :raises RuntimeError: If the result indicates an error.
        """
        if result == 0:
            if error_code is None:
                
                log.info(f"{function_name}: {self.ERROR_CODES.get(result, 'OK')}")
            else:
                raise Exception(
                    f"{function_name}: {self.ERROR_CODES.get(result, 'OK')} ({error_code}: {self.ERROR_CODES.get(error_code, 'Unknown error')})."
                )
        else:
            error_msg = self.ERROR_CODES.get(result, f"Unknown error code {result}")
            full_error_msg = f"{function_name} failed. {error_msg}."

            log.error(full_error_msg)

            raise RuntimeError(full_error_msg)

    def config_server(self, url: str) -> bool:
        """
        Configures the server using a URL.

        :param url: The URL to fetch the server configuration.
        :return: True if configuration was successful, False otherwise.
        """
        if not url.startswith(("http://", "https://")):
            raise ValueError("Invalid URL format.")

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            server_data = response.text.strip().encode("utf-8") + b"\x00"
            result = self.card_encoder_dll.CE_ConfigServer(server_data)
            self._handle_result("CE_ConfigServer", result)
            return True
        except requests.RequestException as e:
            log.error(f"Failed to fetch server data: {e}")
            raise RuntimeError("Network request failed.") from e

    def generate_sector_data(
        self,
        hotel_info: str,
        sector_data: ctypes.Array,
        is_lowest_sector: bool,
        build_no: int,
        floor_no: int,
        mac: str,
        timestamp: int,
        allow_lock_out: bool,
    ) -> List[int]:
        """
        Generates sector data.

        :param hotel_info: Hotel information.
        :param sector_data: Pre-allocated buffer for storing sector data.
        :param is_lowest_sector: Whether this is the lowest sector.
        :param build_no: Building number.
        :param floor_no: Floor number.
        :param mac: MAC address of the lock.
        :param timestamp: Expiration timestamp.
        :param allow_lock_out: Whether lock-out is allowed.
        :return: List of sector data bytes if successful.
        :raises RuntimeError: If the function fails.
        """
        try:
            # Validate input types.
            if not isinstance(sector_data, ctypes.Array):
                raise ValueError("sector_data must be a ctypes Array.")

            # Convertions.
            hotel_info_bytes = hotel_info.encode("utf-8") + b"\x00"
            mac_bytes = mac.encode("utf-8") + b"\x00"

            # Call the DLL function.
            result = self.card_encoder_dll.CE_GenerateSectorData(
                hotel_info_bytes,
                sector_data,
                is_lowest_sector,
                build_no,
                floor_no,
                mac_bytes,
                timestamp,
                allow_lock_out,
            )

            # Handle error 304 directly before using _handle_result.
            if result == 304:
                log.warning(
                    f"CE_GenerateSectorData returned 304: Insufficient sector space."
                )
                return result  # Return 304 to handle it in the main loop.

            # Handle result with error checking - only log success, return error codes for caller to handle
            if result == 0:
                log.info(f"CE_GenerateSectorData: Success")
                return list(sector_data)
            else:
                # Return error code instead of throwing exception so caller can handle it
                error_msg = self.ERROR_CODES.get(result, f"Unknown error code {result}")
                log.warning(f"CE_GenerateSectorData returned error {result}: {error_msg}")
                return result

        except Exception as e:
            
            log.error(f"Unexpected error in CE_GenerateSectorData: {e}")
            raise RuntimeError("Failed to generate sector data.") from e

    def generate_sector_data_server(
        self,
        hotel_info: str,
        sector_data: str,
        is_lowest_sector: bool,
        build_no: int,
        floor_no: int,
        mac: str,
        server_timestamp: str,
        lock_timezone: str,
        allow_lockout: bool,
    ) -> int:
        """
        Calls `CE_GenerateSectorData_Server` from the DLL to generate sector data.

        Args:
            hotel_info (str): Hotel information.
            sector_data (str): Sector data to be written.
            is_lowest_sector (bool): Whether this is the lowest sector.
            build_no (int): Building number.
            floor_no (int): Floor number.
            mac (str): MAC address of the lock.
            server_timestamp (str): Timestamp from the server in "YYYY-MM-DDTHH:MM:SSZ".
            lock_timezone (str): Lock's timezone (e.g., "GMT+3", "GMT-5").
            allow_lockout (bool): Whether lockout is allowed.

        Returns:
            int: The result code from the DLL.
        """
        try:
            # Convert timestamp to lock's timezone
            time_str = CardEncoderDllUtils.convert_timestamp_to_lock_timezone(
                server_timestamp, lock_timezone
            )
            if not time_str:
                log.error("Failed to convert timestamp for lock timezone.")
                return -1

            result = self.card_encoder_dll.CE_GenerateSectorData_Server(
                hotel_info.encode("utf-8"),
                sector_data.encode("utf-8"),
                ctypes.c_bool(is_lowest_sector),
                ctypes.c_int(build_no),
                ctypes.c_int(floor_no),
                mac.encode("utf-8"),
                time_str.encode("utf-8"),
                ctypes.c_bool(allow_lockout),
            )

            return result

        except Exception as e:
            
            log.error(f"Exception in CE_GenerateSectorData_Server: {e}")
            return -1

    def generate_cancel_sector_data(
        self,
        hotel_info: str,
        sector_data: ctypes.Array,
        is_lowest_sector: bool,
        uid: str,  # str decimal. NO HEX.
        timestamp: int,
    ) -> List[int]:
        """
        Generates cancel sector data.

        :param hotel_info: Hotel information.
        :param sector_data: Pre-allocated buffer for storing cancel sector data.
        :param is_lowest_sector: Whether this is the lowest sector.
        :param uid: Unique identifier of the card.
        :param timestamp: Timestamp for the cancel operation.
        :return: List of cancel sector data bytes if successful.
        :raises RuntimeError: If the function fails.
        """
        try:
            # Validate UID is decimal str.
            if not uid.isdigit():
                raise ValueError(
                    f"UID '{uid}' is not a valid decimal number (no hex allowed)."
                )

            # Validate input types.
            if not isinstance(sector_data, ctypes.Array):
                raise ValueError("sector_data must be a ctypes Array.")

            # Convertions.
            hotel_info_bytes = hotel_info.encode("utf-8") + b"\x00"
            uid_bytes = uid.encode("utf-8") + b"\x00"

            # Call the DLL function.
            result = self.card_encoder_dll.CE_GenerateCancelCardData(
                hotel_info_bytes, sector_data, is_lowest_sector, uid_bytes, timestamp
            )

            # Manejar el error 304 directamente antes de usar _handle_result.
            if result == 304:
                log.warning(
                    f"CE_GenerateCancelCardData returned 304: Insufficient sector space."
                )
                return result  # Return 304 to handle it in the main loop.

            # Handle result with error checking - only log success, return error codes for caller to handle
            if result == 0:
                log.info(f"CE_GenerateCancelCardData: Success")
                return list(sector_data)
            else:
                # Return error code instead of throwing exception so caller can handle it
                error_msg = self.ERROR_CODES.get(result, f"Unknown error code {result}")
                log.warning(f"CE_GenerateCancelCardData returned error {result}: {error_msg}")
                return result

        except Exception as e:
            
            log.error(f"Unexpected error in generate_cancel_sector_data: {e}")
            raise RuntimeError("Failed to generate cancel sector data.") from e

    def generate_cancel_card_data_server(
        self,
        hotel_info: str,
        sector_data: str,
        is_lowest_sector: bool,
        uid: str,
        server_timestamp: str,
        lock_timezone: str,
    ) -> int:
        """
        Calls `CE_GenerateCancelCardData_Server` from the DLL to generate cancellation data.

        Args:
            hotel_info (str): Hotel information.
            sector_data (str): Sector data to be written.
            is_lowest_sector (bool): Whether this is the lowest sector.
            uid (str): Card UID.
            server_timestamp (str): Timestamp from the server in "YYYY-MM-DDTHH:MM:SSZ".
            lock_timezone (str): Lock's timezone (e.g., "GMT+3", "GMT-5").

        Returns:
            int: The result code from the DLL.
        """
        try:
            # Convert timestamp to lock's timezone
            time_str = CardEncoderDllUtils.convert_timestamp_to_lock_timezone(
                server_timestamp, lock_timezone
            )
            if not time_str:
                log.error("Failed to convert timestamp for lock timezone.")
                return -1

            result = self.card_encoder_dll.CE_GenerateCancelCardData_Server(
                hotel_info.encode("utf-8"),
                sector_data.encode("utf-8"),
                ctypes.c_bool(is_lowest_sector),
                uid.encode("utf-8"),
                time_str.encode("utf-8"),
            )

            return result

        except Exception as e:
            
            log.error(f"Exception in CE_GenerateCancelCardData_Server: {e}")
            return -1
