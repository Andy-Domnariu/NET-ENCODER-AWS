
import sys, os, ctypes, json, time
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
from typing import Optional
from src.lib.utils.logger import Logger
from src.lib.card_encoder_dll.card_encoder_dll_interface import CardEncoderDLLInterface

log = Logger("card_encoder_dll_service")

class CardEncoderDLLService:
    def __init__(self):
        """
        Initializes the service by creating an instance of the DLL interface.
        """
        self.interface = CardEncoderDLLInterface()
        
    def generate_card_data(
        self,
        hotel_info: str,
        card_uid: str = "",  # Make card_uid optional with a default empty string
        whitelist_data: list[dict] = None,  # Make whitelist_data optional with a default None
        blacklist_data: Optional[list[dict]] = None,
    ) -> dict[str, str]:
        """
        Processes whitelist and blacklist objects using a 48-byte buffer for DLL calls.
        It maintains sector data across both whitelist and blacklist processing.
        Blocks are stored only when error 304 occurs.
        """
        timings = {}
        t0 = time.time()
        
        # Initialize with empty lists if None is provided
        whitelist_data = whitelist_data or []
        blacklist_data = blacklist_data or []
        
        # Always log critical information
        log.info(f"generate_card_data() called with hotel_info and {len(whitelist_data)} whitelist entries, {len(blacklist_data)} blacklist entries")
        log.info(f"card_whitelist_data: {whitelist_data}")
        log.info(f"hotel_info: {hotel_info}")
        log.info(f"card_uid: {card_uid}")
        log.info(f"Regular data count: {len(whitelist_data) if whitelist_data else 0}")
        log.info(f"Blacklist data count: {len(blacklist_data) if blacklist_data else 0}")

        timings["data_reception"] = time.time() - t0
        t1 = time.time()
        
        # Initialize a 48-byte buffer.
        sector_data = (ctypes.c_ubyte * 48)()

        # Cache last sector data.
        cache_last_sector_data = None

        # Initialize in lowest sector.
        is_lowest_sector = True

        # List to store flushed sectors.
        final_sector_data = []

        # List of formatted data blocks.
        formatted_data_blocks: dict[str, str] = {}

        log.info(f"whitelist_data: {whitelist_data}")
        log.info(f"blacklist_data: {blacklist_data}")
        
        # Merge whitelist and blacklist processing into a single loop.
        full_data_list = [{"type": "whitelist", **item} for item in whitelist_data or []] + \
                        [{"type": "blacklist", **item} for item in blacklist_data or []]
        
        log.info(f"full_data_list: {full_data_list}")
        log.info(f"Processing {len(full_data_list)} total entries.")

        timings["data_preparation"] = time.time() - t1
        t2 = time.time()

        i = 0
        while i < len(full_data_list):
            item = full_data_list[i]
            entry_type = item["type"]

            # Extract necessary values
            mac_raw = item.get("mac", "").replace(":", "") if entry_type == "whitelist" else None
            
            # Handle UID conversion safely
            uid_decimal = None
            if entry_type == "blacklist" and "uid" in item:
                try:
                    uid_decimal = str(int(item["uid"], 16))
                except (ValueError, TypeError):
                    log.error(f"Invalid UID format in blacklist entry: {item.get('uid')}")
                    # Use card_uid as a fallback if available
                    if card_uid:
                        try:
                            uid_decimal = str(int(card_uid, 16))
                            log.info(f"Using card_uid as fallback for blacklist entry: {uid_decimal}")
                        except (ValueError, TypeError):
                            log.error(f"Invalid card_uid format: {card_uid}")
            
            time_in_seconds = item.get("timestamp", 0) if entry_type == "whitelist" else item.get("endDate", 0)

            # Log the processing step
            log.info(f"Processing {entry_type} entry {i + 1} with data: {item}")
            log.debug(f"Before DLL call - Current sector data buffer: {bytes(sector_data[:]).hex().upper()}")

            try:
                # Log BEFORE calling DLL
                log.info(f"Calling DLL for {entry_type}: hotel_info={hotel_info}, is_lowest_sector={is_lowest_sector}, mac_raw={mac_raw}, uid_decimal={uid_decimal}, time_in_seconds={time_in_seconds}")

                build_no = int(item.get("build_no") or item.get("buildNo") or 0)
                floor_no = int(item.get("floor_no") or item.get("floorNo") or 0)
                allow_lock_out = int(bool(item.get("allow_lock_out") or item.get("allowLockOut") or False))

                mac_raw = item.get("mac", "")
                mac_raw_str = str(mac_raw)

                if mac_raw_str in ("", "00000000", "0"):
                    mac_raw = "5F638A2E6321"
                else:
                    mac_raw = mac_raw_str
                                  
                log.info("Calling DLL for whitelist: ")
                log.info(f"hotel_info={hotel_info},"
                            f"is_lowest_sector={is_lowest_sector},"
                            f"mac={mac_raw},"
                            f"build_no={build_no},"
                            f"floor_no={floor_no},"
                            f"timestamp={time_in_seconds},"
                            f"allow_lock_out={allow_lock_out}")

                if entry_type == "whitelist":
                    result = self.interface.generate_sector_data(
                        hotel_info=hotel_info,
                        sector_data=sector_data,
                        is_lowest_sector=bool(is_lowest_sector),
                        build_no=build_no,
                        floor_no=floor_no,
                        mac=mac_raw,
                        timestamp=time_in_seconds,
                        allow_lock_out=allow_lock_out,
                    )

                else:  # blacklist
                    # Skip blacklist entry if uid_decimal is None
                    if uid_decimal is None:
                        log.warning(f"Skipping blacklist entry {i + 1} due to missing or invalid UID")
                        i += 1
                        continue
                        
                    result = self.interface.generate_cancel_sector_data(
                        hotel_info=hotel_info,
                        sector_data=sector_data,
                        is_lowest_sector=is_lowest_sector,
                        uid=uid_decimal,
                        timestamp=time_in_seconds,
                    )

                # Log AFTER DLL call
                log.debug(f"DLL response: {result}")
                log.debug(f"After DLL call - sector_data: {bytes(sector_data[:]).hex().upper()}")

                # Check the result.
                if isinstance(result, list):
                    log.info(f"{entry_type.capitalize()} entry {i + 1} processed successfully.")
                    sector_data = (ctypes.c_ubyte * 48)(*result)
                    cache_last_sector_data = sector_data
                    log.info(f"Updated sector data buffer: {bytes(sector_data[:]).hex().upper()}")
                    i += 1  # move to next entry.

                elif isinstance(result, ctypes.Array):
                    log.info(f"{entry_type.capitalize()} entry {i + 1} processed successfully (ctypes array).")
                    sector_data = result
                    cache_last_sector_data = sector_data
                    log.info(f"Updated sector data buffer: {bytes(sector_data[:]).hex().upper()}")
                    i += 1  # move to next entry.

                elif result == 304:  # Error "Insufficient sector space".
                    log.warning(f"{entry_type.capitalize()} entry {i + 1} hit 304 (Insufficient sector space). Storing sector.")

                    # Append only if 304 is encountered.
                    if cache_last_sector_data:
                        log.info(f"Appending sector data to final_sector_data: {bytes(cache_last_sector_data[:]).hex().upper()}")
                        final_sector_data.append(bytes(cache_last_sector_data[:]).hex().upper())

                    # Reset the buffer.
                    sector_data = (ctypes.c_ubyte * 48)()

                    # Change "is_lowest_sector" for all subsequent iterations, including the current retry.
                    is_lowest_sector = False

                else:
                    log.error(f"Failed to generate sector data for {entry_type} entry {i + 1}. Error code: {result}")

            except Exception as e:
                log.error(f"Exception encountered while processing {entry_type} entry {i + 1}: {e}")
                break

        # Log before returning final_sector_data
        log.info(f"Final sector data after processing: {final_sector_data}")
        
        # If we processed all entries without any 304 errors, we need to append the final sector data
        if cache_last_sector_data and not final_sector_data:
            log.info("No 304 errors encountered, appending the final sector data")
            final_sector_data.append(bytes(cache_last_sector_data[:]).hex().upper())
            log.info(f"Appended final sector data: {final_sector_data}")

        # --------------------------
        # FINAL FORMATTING
        # --------------------------
        final_blocks = [
            entry[i: i + 32]
            for entry in final_sector_data
            for i in range(0, len(entry), 32)
        ]
        
        log.info(f"final_blocks {final_blocks}")

        key = 4
        skip_values = {i for i in range(7, 100, 4)}

        for block in final_blocks:
            while key in skip_values:
                key += 1
            formatted_data_blocks[str(key)] = block
            key += 1

        # Always log the final formatted data
        formatted_json = json.dumps(formatted_data_blocks, indent=4)
        timings["total"] = time.time() - t0  # Add total time measurement
        log.info(f"Final formatted data blocks: {formatted_json}")
        log.info(f"⏱ Detailed timings: {json.dumps(timings, indent=2)}")

        return formatted_data_blocks
    