import sys, os, time, json
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
from typing import Dict, List, Optional, Union, Tuple
from src.lib.utils.logger import Logger
from src.lib.utils.utils import Utils
from src.lib.hf_reader_dll.hf_reader_dll_interface import HFReaderDLLInterface
from src.lib.hf_reader_dll.hf_reader_dll_utils import HFReaderDLLUtils
from src.lib.card_encoder_dll.card_encoder_dll_utils import CardEncoderDllUtils

# Configurable logging levels
LOG_INFO = False  # Set to True to enable detailed info logs
LOG_WARNING = True  # Set to True to enable warning logs
LOG_ERROR = True  # Always keep error logs enabled

log = Logger("hf_reader_dll_service")

class HFReaderDLLService:
    """
    A class that provides functionality to prepare and read all sectors of a Mifare 1K card.
    """

    def __init__(self, use_server_mode: bool = False):
        """
        Initialize the CardReader class.
        Currently, it does not require any specific initialization parameters.
        """
        
        # self.use_server_mode = use_server_mode
        self.encoder_service = CardEncoderDllUtils()
        pass

    def read_card_uid(self, ip_address: str, port: int) -> dict:
        """
        Reads the UID of a card.

        :param ip_address: IP address of the HF reader.
        :param port: Port number of the HF reader.
        :return: Dictionary with UID in hexadecimal format or error information.
        """
        if LOG_INFO:
            log.info("read_card_uid")

        reader = HFReaderDLLInterface()
        com_addr = None
        frm_handle = None
        uid_hex = None

        try:
            # Open the reader connection and retrieve UID
            com_addr, frm_handle, uid_hex, auth_result, key_hex = reader.open_sector(
                ip_address, port, sector=0, key_list=None  # sector=0 for UID retrieval
            )

            if uid_hex is None:
                if LOG_ERROR:
                    log.error("Failed to retrieve card UID.")
                return {"success": False, "error": "Failed to retrieve card UID."}

            return {"success": True, "uid": uid_hex}

        except Exception as e:
            if LOG_ERROR:
                log.error(f"Error in read_card_uid: {e}")
            return {"success": False, "error": str(e)}

        finally:
            try:
                if hasattr(reader, "disconnect"):  
                    reader.disconnect()
            except Exception as close_e:
                if LOG_ERROR:
                    log.error(f"Error disconnecting reader: {close_e}")

    def read_card_data(self, ip_address: str, port: int, ic_keys=None) -> dict:
        """
        Reads all sectors and blocks from a Mifare 1K card, following the correct flow:
        1. Open sector
        2. Read blocks
        3. Close sector
        4. Move to the next sector

        :param ip_address: IP address of the HF reader.
        :param port: Port number of the HF reader.
        :param ic_keys: List of hex keys for authentication (optional).
        :return: Dictionary containing block data or error messages.
        """
        log.info("read_card_data")

        ic_keys_bytes = []
        if ic_keys:
            try:
                ic_keys_bytes = [bytes.fromhex(key) for key in ic_keys if isinstance(key, str)]
            except ValueError as e:
                log.error(f"Invalid ic_key format provided: {ic_keys}. Error: {e}")
                return {"error": "Invalid ic_key format. Must be a valid hex string."}

        start_time = time.time()
        response_data = {}

        reader = HFReaderDLLInterface()

        try:
            for sector in range(16):  # Mifare 1K has 16 sectors (0-15)
                log.info(f"Attempting to authenticate sector {sector}...")

                try:
                    com_addr, frm_handle, uid_hex, auth_result, key_hex = reader.open_sector(
                        ip_address, port, sector, ic_keys_bytes
                    )
                    
                    if not auth_result:
                        log.warning(f"Sector {sector}: Authentication failed. Skipping reading.")
                        continue  

                    first_block = sector * 4

                    for block_num in range(first_block, first_block + 4):  
                        try:
                            data = reader.iso14443a_read(com_addr, block_num, frm_handle)

                            if isinstance(data, (bytes, bytearray)):
                                hex_data = data.hex().upper()
                            elif isinstance(data, str):  
                                hex_data = data.upper()
                            else:
                                log.warning(f"Unexpected data type for block {block_num}: {type(data)}")
                                hex_data = "READ_FAIL"

                            log.info(f"Successfully read block {block_num}: {hex_data}")
                            response_data[str(block_num)] = hex_data  

                        except Exception as read_error:
                            log.error(f"Exception while reading block {block_num}: {read_error}")
                            response_data[str(block_num)] = "ERROR"

                    log.info(f"Completed sector {sector} read successfully.")
                    
                except Exception as sector_error:
                    log.error(f"Exception while handling sector {sector}: {sector_error}")
                    response_data[f"sector_{sector}"] = "AUTH_ERROR"
                    
            log.info("Successfully read all sectors and blocks.")

        except Exception as e:
            if LOG_ERROR:
                log.error(f"An error occurred in read_card_data: {e}")
            return {"error": str(e)}

        finally:
            try:
                if hasattr(reader, "disconnect"):
                    reader.disconnect()
            except Exception as close_e:
                if LOG_ERROR:
                    log.error(f"Error disconnecting reader: {close_e}")

            elapsed_time = time.time() - start_time
            log.info(f"Card reading completed in {elapsed_time:.2f} seconds.")

        return response_data


    # def write_card_data(
    #     self, 
    #     ip_address: str, 
    #     port: int, 
    #     formatted_data_blocks: Union[str, Dict[str, str]], 
    #     decrypted_ic_key_hex: str
    # ) -> Dict[str, Union[bool, str]]:       
    #     """
    #     Writes the JSON-formatted sector data to the card, including trailer blocks.

    #     :param ip_address: The IP address of the reader.
    #     :param port: The port number for the reader.
    #     :param formatted_data_blocks: A dictionary where each key is a block number and value is the hex-encoded data.
    #                                 (It can also be a JSON string that represents such a dictionary.)
    #     :param decrypted_ic_key_hex: Decrypted key in hex string format.
    #     :return: Dictionary containing success status, UID, and final output.
    #     """
    #     start_time = time.time()
    #     encoder = None  # Ensure encoder exists for safe closure in `finally`
        
    #     try:
    #         # Step 1: Prepare the reader
    #         encoder, com_addr, frm_handle, uid = HFReaderDLLUtils.prepare_reader(ip_address, port)
    #         if not encoder or not uid:
    #             log.error("Failed to prepare the reader.")
    #             return {"success": False, "error": "Failed to prepare the reader."}

    #         uid_hex = uid.hex().upper()
    #         log.info(f"Card UID: {uid_hex}")  # Log UID
            
    #         # Convert the IC key from hex string to bytes.
    #         try:
    #             ic_key_bytes = bytes.fromhex(decrypted_ic_key_hex)
    #         except ValueError:
    #             log.error("Invalid IC key format provided.")
    #             return {"success": False, "error": "Invalid IC key format."}

    #         log.info("write_card_data started.")

    #         # If formatted_data_blocks is a JSON string, convert it to a dict
    #         if isinstance(formatted_data_blocks, str):
    #             try:
    #                 formatted_data_blocks = json.loads(formatted_data_blocks)
    #             except json.JSONDecodeError:
    #                 log.error("Invalid JSON format in formatted_data_blocks.")
    #                 return {"success": False, "error": "Invalid JSON format."}

    #         # Dictionary to track which sectors have been processed
    #         processed_sectors = set()

    #         # Process each data block in the formatted dictionary
    #         for block, hex_str in formatted_data_blocks.items():
    #             if not isinstance(hex_str, str) or len(hex_str) != 32 or not Utils.is_hexadecimal(hex_str):
    #                 log.error(f"Invalid data in block {block}: {hex_str}")
    #                 return {"success": False, "error": f"Invalid data in block {block}"}

    #             block_number = int(block)  # Convert block key (string) to an integer
    #             sector_number = block_number // 4  # Calculate sector number (sector 0 is reserved)

    #             # Authenticate the sector if not done already.
    #             if sector_number not in processed_sectors:
    #                 if not HFReaderDLLUtils.auth_sector(
    #                     encoder, com_addr, frm_handle, sector_number, [ic_key_bytes],
    #                     ip_address, port
    #                 ):
    #                     log.error(f"Authentication failed for sector {sector_number}.")
    #                     return {"success": False, "error": f"Authentication failed for sector {sector_number}."}
    #                 processed_sectors.add(sector_number)

    #             # Convert the hex string to bytes.
    #             block_bytes = bytes.fromhex(hex_str)

    #             # Write the block data.
    #             result = encoder.write_block_dll_wrapper(com_addr, block_number, block_bytes, frm_handle)
    #             if result != 0:
    #                 log.error(f"Failed writing block {block_number}. Error: {result}")
    #                 return {"success": False, "error": f"Failed writing block {block_number}. Error: {result}"}

    #         # After writing all data blocks, process trailer blocks.
    #         for sector_number in processed_sectors:
    #             trailer_block = sector_number * 4 + 3  # Trailer block position

    #             # Re-authenticate the sector before writing the trailer block.
    #             if not HFReaderDLLUtils.auth_sector(
    #                 encoder, com_addr, frm_handle, sector_number, [ic_key_bytes],
    #                 ip_address, port
    #             ):
    #                 log.error(f"Re-authentication failed for trailer block in sector {sector_number}.")
    #                 return {"success": False, "error": f"Re-authentication failed for trailer block in sector {sector_number}."}

    #             # Construct trailer block data.
    #             access_bits = bytes.fromhex("FF0780")  # 3 bytes of access bits
    #             user_data = bytes.fromhex("69")        # 1 byte user data

    #             # Construct full 16-byte trailer block: KeyA + Access Bits + User Byte + KeyB.
    #             trailer_data = ic_key_bytes + access_bits + user_data + ic_key_bytes

    #             # Write the trailer block.
    #             result = encoder.write_block_dll_wrapper(com_addr, trailer_block, trailer_data, frm_handle)
    #             if result != 0:
    #                 log.error(f"Failed writing trailer block {trailer_block} in sector {sector_number}. Error: {result}")
    #                 return {"success": False, "error": f"Failed writing trailer block {trailer_block} in sector {sector_number}. Error: {result}"}

    #             log.info(f"Trailer block {trailer_block} written successfully for sector {sector_number}.")

    #         log.info("All data blocks and trailer blocks written successfully.")
            
    #         return {
    #             "success": True,
    #             "output": trailer_data.hex().upper(),  # Keep the final output JSON
    #             "uid": uid_hex  # Include the UID in hex format
    #         }

    #     except Exception as e:
    #         log.error(f"An error occurred in write_card_data: {e}")
    #         return {"success": False, "error": str(e)}

    #     finally:
    #         # Always close the connection, even if an exception occurs
    #         if encoder:
    #             encoder.close_rf_field_dll_wrapper(com_addr, frm_handle)
    #             encoder.close_net_port_dll_wrapper(frm_handle)
    #         elapsed_time = time.time() - start_time
    #         log.info(f"Card writing completed in {elapsed_time:.2f} seconds.")
            
    def write_card_data(self, ip_address: str, port: int, write_data: dict, ic_keys=None) -> dict:
        """
        Writes data to the Mifare 1K card, ensuring sector-based authentication and valid data processing.

        :param ip_address: IP address of the HF reader.
        :param port: Port number of the HF reader.
        :param write_data: Dictionary where keys are block numbers, and values are hex-encoded data strings.
        :param ic_keys: List of decrypted hex keys for authentication.
        :return: Dictionary indicating the success or failure of each block.
        """
        if LOG_INFO:
            log.info("write_card_data")

        ic_keys_bytes = []
        if ic_keys:
            try:
                if isinstance(ic_keys, str):  
                    ic_keys = [ic_keys.strip()]  # Convert single string to a list

                if not isinstance(ic_keys, list):
                    raise ValueError("ic_keys should be a list of strings.")

                # Keep the original string keys for open_sector
                ic_keys_str = [key for key in ic_keys if Utils.is_hexadecimal(key)]
                
                # Also convert to bytes for other operations if needed
                ic_keys_bytes = [bytes.fromhex(key) for key in ic_keys]
            except ValueError as e:
                if LOG_ERROR:
                    log.error(f"Invalid ic_key format provided: {ic_keys}. Error: {e}")
                return {"error": "Invalid ic_key format. Must be a valid hex string."}

        start_time = time.time()
        response_data = {}

        reader = HFReaderDLLInterface()

        try:
            processed_sectors = set()

            for block_num, hex_str in write_data.items():
                try:
                    if not isinstance(hex_str, str) or len(hex_str) != 32 or not Utils.is_hexadecimal(hex_str):
                        if LOG_ERROR:
                            log.error(f"Invalid data for block {block_num}: {hex_str}")
                        response_data[str(block_num)] = "INVALID_DATA"
                        continue

                    block_num = int(block_num)
                    sector = block_num // 4  # Each sector has 4 blocks

                    if sector not in processed_sectors:
                        if LOG_INFO:
                            log.info(f"Attempting to authenticate sector {sector}...")

                        com_addr, frm_handle, uid_hex, auth_result, key_hex = reader.open_sector(
                            ip_address, port, sector, ic_keys_str
                        )

                        if not auth_result:
                            if LOG_WARNING:
                                log.warning(f"Sector {sector}: Authentication failed. Skipping writing.")
                            continue

                        processed_sectors.add(sector)

                    # Pass the hex string directly to iso14443a_write, not the bytes
                    result = reader.iso14443a_write(com_addr, block_num, hex_str, frm_handle)

                    if result:
                        if LOG_INFO:
                            log.info(f"Successfully wrote to block {block_num}: {hex_str}")
                        # Store the actual data instead of just "WRITE_SUCCESS"
                        response_data[str(block_num)] = hex_str
                    else:
                        if LOG_WARNING:
                            log.warning(f"Failed to write block {block_num}.")
                        response_data[str(block_num)] = "WRITE_FAIL"

                except Exception as write_error:
                    if LOG_ERROR:
                        log.error(f"Exception while writing to block {block_num}: {write_error}")
                    response_data[str(block_num)] = "ERROR"

            if LOG_INFO:
                log.info("Successfully processed all sectors for writing.")
            
            # After writing all data blocks, process trailer blocks
            if LOG_INFO:
                log.info("Writing trailer blocks for all processed sectors...")
            
            # Get the first key from ic_keys_bytes to use for trailer blocks
            if not ic_keys_bytes:
                if LOG_WARNING:
                    log.warning("No IC keys available for trailer blocks. Skipping trailer block writing.")
            else:
                ic_key_bytes = ic_keys_bytes[0]  # Use the first key
                
                for sector_number in processed_sectors:
                    try:
                        trailer_block = sector_number * 4 + 3  # Trailer block position
                        
                        # Skip sector 0 trailer block as it's typically protected
                        if sector_number == 0:
                            if LOG_INFO:
                                log.info("Skipping trailer block for sector 0 (protected).")
                            continue
                            
                        if LOG_INFO:
                            log.info(f"Writing trailer block for sector {sector_number} (block {trailer_block})...")
                        
                        # Construct trailer block data
                        access_bits = bytes.fromhex("FF0780")  # 3 bytes of access bits
                        user_data = bytes.fromhex("69")        # 1 byte user data
                        
                        # Construct full 16-byte trailer block: KeyA + Access Bits + User Byte + KeyB
                        trailer_data = ic_key_bytes + access_bits + user_data + ic_key_bytes
                        
                        # Convert to hex string for iso14443a_write
                        trailer_hex = trailer_data.hex().upper()
                        
                        # Write the trailer block
                        result = reader.iso14443a_write(com_addr, trailer_block, trailer_hex, frm_handle)
                        
                        if result:
                            if LOG_INFO:
                                log.info(f"Successfully wrote trailer block {trailer_block} for sector {sector_number}")
                            # Store the actual trailer data
                            response_data[str(trailer_block)] = trailer_hex
                        else:
                            if LOG_WARNING:
                                log.warning(f"Failed to write trailer block {trailer_block} for sector {sector_number}")
                            response_data[str(trailer_block)] = "TRAILER_WRITE_FAIL"
                            
                    except Exception as trailer_error:
                        if LOG_ERROR:
                            log.error(f"Error writing trailer block for sector {sector_number}: {trailer_error}")
                        response_data[f"trailer_{sector_number}"] = "TRAILER_ERROR"

        except Exception as e:
            if LOG_ERROR:
                log.error(f"An error occurred in write_card_data: {e}")
            return {"success": False, "error": str(e)}

        finally:
            try:
                if hasattr(reader, "disconnect"): 
                    reader.disconnect()
            except Exception as close_e:
                if LOG_ERROR:
                    log.error(f"Error disconnecting reader: {close_e}")

            elapsed_time = time.time() - start_time
            if LOG_INFO:
                log.info(f"Card writing completed in {elapsed_time:.2f} seconds.")

        # Check if any blocks failed to write
        if any(status == "WRITE_FAIL" or status == "ERROR" or status == "INVALID_DATA" or 
               status == "TRAILER_WRITE_FAIL" or status == "TRAILER_ERROR" 
               for status in response_data.values()):
            return {
                "success": False, 
                "blocks": response_data, 
                "error": "Some blocks failed to write",
                "uid": uid_hex if 'uid_hex' in locals() else None
            }
        else:
            return {
                "success": True, 
                "blocks": response_data,
                "uid": uid_hex if 'uid_hex' in locals() else None
            }

    def write_reset_data(self, ip_address: str, port: int, decrypted_ic_key_hex: Optional[Union[str, list]] = None) -> Dict[str, Union[bool, str]]:
        """
        Writes zeros to all sectors (except sector 0) to reset the card and restore factory-like trailer blocks.
        """
        start_time = time.time()
        response_data = {}

        reader = HFReaderDLLInterface()
        active_session = None

        try:
            log.info("Starting card reset operation...")

            ic_keys_bytes = []
            ic_keys_str = []

            if decrypted_ic_key_hex:
                try:
                    if isinstance(decrypted_ic_key_hex, str):  # Single key
                        ic_keys_str = [decrypted_ic_key_hex.strip()]
                        ic_keys_bytes = [bytes.fromhex(decrypted_ic_key_hex.strip())]

                    elif isinstance(decrypted_ic_key_hex, list):  # Multiple keys
                        ic_keys_str = [key.strip() for key in decrypted_ic_key_hex if isinstance(key, str)]
                        ic_keys_bytes = [bytes.fromhex(key.strip()) for key in decrypted_ic_key_hex if isinstance(key, str)]

                except ValueError:
                    log.error("Invalid decrypted IC key format.")
                    return {"success": False, "error": "Invalid decrypted IC key format."}

            # Default to factory key "FFFFFFFFFFFF" if no decrypted IC key is available
            if not ic_keys_str:
                ic_keys_str = ["FFFFFFFFFFFF"]

            processed_sectors = set()

            # 🔹 Open a Single Connection Session Before Authentication
            log.info("Opening initial connection session for reset process...")
            com_addr, frm_handle, uid_hex, session_active, key_hex = reader.open_sector(
                ip_address, port, 1, ic_keys_str  # Use sector 1 for initial auth
            )

            if not session_active:
                log.error("Initial sector authentication failed. Exiting reset process.")
                return {"success": False, "error": "Failed to establish authentication session."}

            active_session = (com_addr, frm_handle)

            for sector_number in range(1, 16):  # Skip sector 0
                log.info(f"Authenticating sector {sector_number} using active session...")

                try:
                    # Use existing session instead of reopening
                    auth_result = reader.auth_existing_sector(com_addr, frm_handle, sector_number, ic_keys_str)

                    if not auth_result:
                        log.warning(f"Sector {sector_number}: Authentication failed. Skipping reset.")
                        continue

                    processed_sectors.add(sector_number)

                    # Write zeros to data blocks (except trailer block)
                    for block_offset in range(3):  # Blocks 0, 1, and 2
                        block_number = sector_number * 4 + block_offset
                        zero_data = "00" * 16  # 16 bytes of zeros as hex
                        result = reader.iso14443a_write(com_addr, block_number, zero_data, frm_handle)

                        if result:
                            log.info(f"Successfully reset block {block_number}")
                            response_data[str(block_number)] = "RESET_SUCCESS"
                        else:
                            log.warning(f"Failed to reset block {block_number}.")
                            response_data[str(block_number)] = "RESET_FAIL"

                except Exception as auth_error:
                    log.error(f"Error authenticating sector {sector_number}: {auth_error}")
                    response_data[str(sector_number)] = "AUTH_FAIL"

            # Process trailer blocks for each authenticated sector
            if not ic_keys_bytes:
                log.warning("No IC keys available for trailer blocks. Skipping trailer block writing.")
            else:
                # Define factory-like trailer key
                trailer_key = bytes.fromhex("FFFFFFFFFFFF")  # Factory default key (6 bytes)
                access_bits = bytes.fromhex("7F0788")        # Example access bits (3 bytes)
                user_data = bytes.fromhex("69")             # 1-byte user data

                for sector_number in processed_sectors:
                    try:
                        trailer_block = sector_number * 4 + 3  # Trailer block position

                        log.info(f"Writing trailer block for sector {sector_number} (block {trailer_block})...")

                        # Construct trailer block to simulate factory default
                        trailer_data = trailer_key + access_bits + user_data + trailer_key
                        trailer_hex = trailer_data.hex().upper()

                        result = reader.iso14443a_write(com_addr, trailer_block, trailer_hex, frm_handle)

                        if result:
                            log.info(f"Successfully wrote factory-style trailer block {trailer_block} for sector {sector_number}")
                            response_data[str(trailer_block)] = trailer_hex
                        else:
                            log.warning(f"Failed to write trailer block {trailer_block} for sector {sector_number}")
                            response_data[str(trailer_block)] = "TRAILER_WRITE_FAIL"

                    except Exception as trailer_error:
                        log.error(f"Error writing trailer block for sector {sector_number}: {trailer_error}")
                        response_data[f"trailer_{sector_number}"] = "TRAILER_ERROR"

            log.info("All data blocks and trailer blocks written successfully for reset.")

        except Exception as e:
            log.error(f"An error occurred in write_reset_data: {e}")
            return {"success": False, "error": str(e)}

        finally:
            try:
                if hasattr(reader, "disconnect"):
                    reader.disconnect()
            except Exception as close_e:
                if LOG_ERROR:
                    log.error(f"Error disconnecting reader: {close_e}")

            elapsed_time = time.time() - start_time
            log.info(f"Card reset operation completed in {elapsed_time:.2f} seconds.")

        if any(status in ["RESET_FAIL", "TRAILER_WRITE_FAIL", "AUTH_FAIL"] for status in response_data.values()):
            return {
                "success": False,
                "blocks": response_data,
                "error": "Some blocks failed to reset",
                "uid": uid_hex if 'uid_hex' in locals() else None
            }
        else:
            return {
                "success": True,
                "blocks": response_data,
                "uid": uid_hex if 'uid_hex' in locals() else None
            }



# def main():
# #     """
# #     Example test entry point for reading, writing, and resetting a MIFARE 1K card.
# #     Demonstrates how to use the HFReaderDLLService for different operations.
# #     """
# #     # Example usage:
#     ip_address = "192.168.1.190"
#     port = 6000

#     # Example IC key as a hex string (the "decrypted" key you want to use).
#     ic_key = "35d807f98f0c"
#     decrypted_ic_key_hex = ic_key  # Define decrypted_ic_key_hex

# #     # Initialize HFReaderDLLService
#     reader_service = HFReaderDLLService()

# # #     # -------------------------------------------------------------------------
# # #     # 1) READ CARD UID (Uncomment to test reading UID)
# # #     # -------------------------------------------------------------------------
#     # uid_result = reader_service.read_card_uid(ip_address, port)
#     # log.info(f"uid read successfully: {uid_result}")
    

# # #     # -------------------------------------------------------------------------
# # #     # 2) READ CARD DATA (Uncomment to test reading the card)
# # #     # -------------------------------------------------------------------------
# # #     # reader_service.read_card_data(ip_address, port, ic_keys=[decrypted_ic_key_hex])

# #     # -------------------------------------------------------------------------
# #     # 3) WRITE CARD DATA (Uncomment to test writing data)
# #     # -------------------------------------------------------------------------

# #     formatted_data_blocks = {
# #     "4": "3DB9B07BD4F0C11492BF1C4921319F65",
# #     "5": "EC3B918D08FCC0DE559BB211D00F079D",
# #     "6": "D368BC6EF9A630F20B3E1FDA6D6D6DC8"
# # }

# #     writer_service = HFReaderDLLService()
# #     writer_service.write_card_data(ip_address, port, formatted_data_blocks, decrypted_ic_key_hex)

# # #     # -------------------------------------------------------------------------
# # #     # 4) RESET CARD DATA (Uncomment to test resetting the card)
# # #     # -------------------------------------------------------------------------
# # #     reset_service = HFReaderDLLService()
# # #     reset_service.write_reset_data(ip_address, port, decrypted_ic_key_hex)

# if __name__ == "__main__":
#     main()