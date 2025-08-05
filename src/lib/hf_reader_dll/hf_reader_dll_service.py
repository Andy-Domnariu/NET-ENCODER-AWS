import sys, os, time, json, requests
from src.lib.omnitec_crypto.omnitec_crypto import OmnitecCrypto
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
from typing import Dict, Optional, Union
from src.lib.utils.logger import Logger
from src.lib.utils.utils import Utils
from src.lib.hf_reader_dll.hf_reader_dll_interface import HFReaderDLLInterface
from src.lib.card_encoder_dll.card_encoder_dll_utils import CardEncoderDllUtils
from src.lib.hf_reader_dll.hf_threadmanager import serialize_by_ip_and_port
from src.lib.card_encoder_dll.card_encoder_dll_service import CardEncoderDLLService

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
        self.encoder_service = CardEncoderDllUtils()
        pass

    @serialize_by_ip_and_port(get_ip_arg_index=1, get_port_arg_index=2)
    def read_card_uid(self, ip_address: str, port: int) -> dict:
        
        log.info("read_card_uid (direct anticoll)")

        log.info("Step 0: About to create DLL instance...")
            
        reader = HFReaderDLLInterface(ip_address, port)
        
        log.info("Step 1: DLL instance created successfully!")
        log.info(f"🔁 Instance ID: {id(reader)}")
        log.info(f"🔁 Instance ID: {id(reader.hf_reader_dll)}")


        try:
            com_addr, frm_handle, uid_hex = reader.connect(ip_address, port)

            reader.com_addr = com_addr
            reader.frm_handle = frm_handle
            reader.uid_hex = uid_hex

            if uid_hex is None:
                log.error("Failed to retrieve card UID.")
                return {"success": False, "error": "Failed to retrieve card UID."}

            return {"success": True, "uid": uid_hex}

        except Exception as e:
            log.error(f"Error in read_card_uid: {e}")
            return {"success": False, "error": str(e)}

        finally:
            try:
                reader.disconnect()
            except Exception as close_e:
                log.error(f"Error disconnecting reader: {close_e}")

    @serialize_by_ip_and_port(get_ip_arg_index=1, get_port_arg_index=2)
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
        log.info(f"ICKEY state at read_card_data start: {ic_keys}")

        # Process IC keys - keep as strings for open_sector
        ic_keys_str = []
        if ic_keys:
            log.info(f"Processing IC keys: {ic_keys}")
            try:
                # Filter out any non-string keys and validate hex strings
                for key in ic_keys:
                    if not isinstance(key, str):
                        log.warning(f"Skipping non-string key: {key}")
                        continue
                        
                    # Validate key is a hex string
                    try:
                        # Just test if it's valid hex, but keep as string
                        _ = bytes.fromhex(key)
                        ic_keys_str.append(key)
                        log.info(f"Valid hex key: {key}")
                    except ValueError as e:
                        log.warning(f"Skipping invalid hex key: {key}. Error: {e}")
                        
            except Exception as e:
                log.error(f"Error processing IC keys: {e}")

        start_time = time.time()
        response_data = {}

        reader = HFReaderDLLInterface(ip_address,port)

        try:
            for sector in range(16):  # Mifare 1K has 16 sectors (0-15)
                print(f"Attempting to authenticate sector {sector}...")
                com_addr, frm_handle, uid_hex, auth_result, key_hex = reader.open_sector(
                    ip_address, port, sector, ic_keys_str
                )

                if not auth_result:
                    # LOG_WARNING eliminado - logging directo
                    log.warning(f"Sector {sector}: Authentication failed with all keys. Skipping reading.")
                    continue  

                first_block = sector * 4

                for block_num in range(first_block, first_block + 4): 
                     
                    try:
                        data = reader.iso14443a_read(com_addr, block_num, frm_handle)
                        if isinstance(data, (bytes, bytearray)):
                            hex_data = data.hex().upper()
                        elif isinstance(data, str):  #  If `data` is already a string, use as is
                            hex_data = data.upper()
                        else:
                            # LOG_WARNING eliminado - logging directo
                            log.warning(f" Unexpected data type for block {block_num}: {type(data)}")
                            hex_data = "READ_FAIL"

                        # LOG_INFO eliminado - logging directo
                        log.info(f" Successfully read block {block_num}: {hex_data}")
                        response_data[str(block_num)] = hex_data

                    except Exception as read_error:
                        # LOG_ERROR eliminado - logging directo
                        log.error(f" Exception while reading block {block_num}: {read_error}")
                        response_data[str(block_num)] = "ERROR"

        except Exception as e:
            # LOG_ERROR eliminado - logging directo
            log.error(f" An error occurred in read_card_data: {e}")
            return {"error": str(e)}

        finally:
            try:
                reader.disconnect()
            except Exception as close_e:
                # LOG_ERROR eliminado - logging directo
                log.error(f" Error disconnecting reader: {close_e}")

            elapsed_time = time.time() - start_time
            # LOG_INFO eliminado - logging directo
            log.info(f" Card reading completed in {elapsed_time:.2f} seconds.")

        return response_data
 
    @serialize_by_ip_and_port(get_ip_arg_index=1, get_port_arg_index=2)
    def write_card_data(self, ip_address: str, port: int, write_data: dict, ic_keys=None) -> dict:
        # LOG_INFO eliminado - logging directo
        log.info("write_card_data called")
        log.info(f"🔑 ICKEY state at write_card_data start: {ic_keys}")

        timings = {}
        t0 = time.time()

        ic_keys_str = []
        if ic_keys:
            try:
                if isinstance(ic_keys, str):
                    # LOG_INFO eliminado - logging directo
                    log.info(f"Converting single ICKEY string to list: {ic_keys}")
                    ic_keys = [ic_keys.strip()]
                if not isinstance(ic_keys, list):
                    # LOG_WARNING eliminado - logging directo
                    log.warning(f"Invalid ICKEY format: {ic_keys}")
                    raise ValueError("ic_keys should be a list of strings.")

                for key in ic_keys:
                    if isinstance(key, str) and Utils.is_hexadecimal(key):
                        ic_keys_str.append(key)
                        # LOG_INFO eliminado - logging directo
                        log.info(f"✅ Valid ICKEY detected: {key}")
                    else:
                        # LOG_WARNING eliminado - logging directo
                        log.warning(f"⚠️ Skipping invalid hex ICKEY: {key}")
            except ValueError as e:
                # LOG_ERROR eliminado - logging directo
                log.error(f"🚫 Invalid ICKEY format: {e}")
                return {"error": "Invalid ic_key format. Must be a valid hex string."}

        if not ic_keys_str:
            # LOG_INFO eliminado - logging directo
            log.info("⚠️ No valid ICKEYS provided, using default factory key FFFFFFFFFFFF.")

        timings["prepare_keys"] = time.time() - t0
        t1 = time.time()

        response_data = {}
        uid_hex = None
        reader = None

        try:
            reader = HFReaderDLLInterface(ip_address, port)
            reader.disconnect()
            timings["dll_instance"] = time.time() - t1

            processed_sectors = set()
            t2 = time.time()
            try:
                reader.disconnect()
                uid_com, uid_frm, uid_hex = reader.connect(ip_address, port)

                if uid_com is None or uid_frm is None:
                    # LOG_ERROR eliminado - logging directo
                    log.error("❌ Cannot write: com_addr or frm_handle is None.")
                    return {"success": False, "output": "Reader not connected. Cannot write card."}
                reader.com_addr = uid_com
                reader.frm_handle = uid_frm
                reader.uid_hex = uid_hex
                # LOG_INFO eliminado - logging directo
                log.info(f"Early UID read success: {uid_hex}")
            except Exception as e:
                # LOG_WARNING eliminado - logging directo
                log.warning(f"Early UID fetch failed: {e}")
                uid_hex = None
            timings["uid_fetch"] = time.time() - t2

            t3 = time.time()
            for block_num, hex_str in write_data.items():
                block_start = time.time()
                try:
                    if not isinstance(hex_str, str) or len(hex_str) != 32 or not Utils.is_hexadecimal(hex_str):
                        # LOG_ERROR eliminado - logging directo
                        log.error(f"Invalid data for block {block_num}: {hex_str}")
                        response_data[str(block_num)] = "INVALID_DATA"
                        continue

                    block_num = int(block_num)
                    sector = block_num // 4

                    if sector not in processed_sectors:
                        reader.disconnect()
                        sector_result = reader.open_sector(ip_address, port, sector, ic_keys_str)

                        if not isinstance(sector_result, tuple) or len(sector_result) != 5:
                            # LOG_ERROR eliminado - logging directo
                            log.error(f"Unexpected response from open_sector (sector {sector}): {sector_result}")
                            response_data[str(block_num)] = "SECTOR_AUTH_ERROR"
                            continue

                        com_addr, frm_handle, uid_hex_tmp, auth_result, key_hex = sector_result

                        if not auth_result:
                            response_data[str(block_num)] = "AUTH_FAIL"
                            continue

                        uid_hex = uid_hex or uid_hex_tmp
                        processed_sectors.add(sector)

                    result = reader.iso14443a_write(com_addr, block_num, hex_str, frm_handle)

                    # ———————————————————————————————————————————————————————————
                    # Si ISO14443AWrite devolvió False, intentamos leer de inmediato
                    # para ver si el dato realmente se grabó en la tarjeta.
                    if not result:
                        # 1) Re-seleccionamos la tarjeta (sin desconectar).
                        reader.iso14443a_select(com_addr, uid_hex, frm_handle)
                        # 2) Leemos ese mismo bloque “en caliente”:
                        data_after = reader.iso14443a_read(com_addr, block_num, frm_handle)
                        # LOG_INFO eliminado - logging directo
                        log.info(f"READ_AFTER_WRITE block {block_num}: {data_after}")
                        # 3) Si coincide con hex_str, lo marcamos como éxito
                        if isinstance(data_after, str) and data_after.upper() == hex_str.upper():
                            result = True
                    # ———————————————————————————————————————————————————————————

                    response_data[str(block_num)] = hex_str if result else "WRITE_FAIL"

                except Exception as write_error:
                    response_data[str(block_num)] = "ERROR"
                finally:
                    timings[f"block_{block_num}_write"] = time.time() - block_start
            timings["data_blocks"] = time.time() - t3

            t4 = time.time()
            if ic_keys_str:
                for sector_number in processed_sectors:
                    trailer_block = sector_number * 4 + 3
                    try:
                        # 1) open_sector ya maneja la lógica: PRIMERO ICKEY hotel, DESPUÉS fallback
                        com_addr, frm_handle, uid_hex_tmp, auth_ok, used_key = \
                            reader.open_sector(ip_address, port, sector_number, ic_keys_str)
                        if not auth_ok:
                            response_data[str(trailer_block)] = "TRAILER_AUTH_FAIL"
                            continue

                        # 2) Para escribir el trailer, debemos autenticar con Key B (modo=1)
                        # Usamos la MISMA llave que funcionó en open_sector, pero con modo=1 (Key B)
                        auth_keyB_result = reader.iso14443a_auth_key(com_addr, 1, sector_number, used_key, frm_handle)
                        
                        if not auth_keyB_result:
                            log.warning(f"No se pudo autenticar con Key B usando la llave {used_key} en sector {sector_number}")
                            response_data[str(trailer_block)] = "TRAILER_KEYB_AUTH_FAIL"
                            continue

                        # 3) Construimos el trailer SIEMPRE con la ICKEY del hotel (primera en la lista)
                        # Formato del trailer: [Key A: 6 bytes][Access Bits: 4 bytes][Key B: 6 bytes]
                        hotel_key = ic_keys_str[0]
                        key_bytes   = bytes.fromhex(hotel_key)        # 6 bytes
                        access_bits = bytes.fromhex("FF078069")       # 4 bytes (Access Bits fábrica + User byte)
                        trailer_hex = (key_bytes + access_bits + key_bytes).hex().upper()

                        # 4) Escribimos el trailer (ahora que tenemos autenticación Key B)
                        result = reader.iso14443a_write(com_addr, trailer_block, trailer_hex, frm_handle)

                        # 5) Verificamos "en caliente" por si el driver devolvió False erróneamente
                        if not result:
                            reader.iso14443a_select(com_addr, uid_hex_tmp, frm_handle)
                            after = reader.iso14443a_read(com_addr, trailer_block, frm_handle)
                            if isinstance(after, str) and after.upper() == trailer_hex:
                                result = True

                        response_data[str(trailer_block)] = trailer_hex if result else "TRAILER_WRITE_FAIL"

                    except Exception as e:
                        log.error(f"Error al escribir trailer block {trailer_block}: {e}")
                        response_data[str(trailer_block)] = "TRAILER_WRITE_FAIL"
            else:
                log.warning("No IC keys available for trailer blocks. Skipping.")
            timings["trailers"] = time.time() - t4

        except Exception as e:
            # LOG_ERROR eliminado - logging directo
            log.error(f"Critical exception in write_card_data: {e}")
            return {"success": False, "error": str(e)}
        finally:
            try:
                if reader:
                    reader.disconnect()
            except Exception as close_e:
                pass

        timings["total"] = time.time() - t0
        log.info(f"⏱ Detailed timings: {json.dumps(timings, indent=2)}")

        failed_blocks = [
            v for v in response_data.values()
            if v in ["WRITE_FAIL", "ERROR", "INVALID_DATA"]
        ]
        return {
            "success": len(failed_blocks) == 0,
            "blocks": response_data,
            "error": "Some blocks failed to write" if failed_blocks else None,
            "uid": uid_hex,
            "timings": timings
        }

    # def _write_card_data(self, ip_address: str, port: int, write_data: dict, ic_keys=None) -> dict:
    #     # LOG_INFO eliminado - logging directo
    #         log.info("Entering _write_card_data")
    #         log.info(f"ICKEY state at _write_card_data start: {ic_keys}")

    #     timings = {}
    #     t0 = time.time()

    #     # 0) Normalizar ic_keys
    #     if isinstance(ic_keys, str):
    #         # LOG_INFO eliminado - logging directo
    #             log.info(f"Converting single ICKEY string to list: {ic_keys}")
    #         ic_keys = [ic_keys.strip()]
    #     if not ic_keys or any(not isinstance(k, str) or not Utils.is_hexadecimal(k) for k in ic_keys):
    #         msg = "IC key inválida o no proporcionada: se necesita al menos una para autenticar sectores."
    #         # LOG_ERROR eliminado - logging directo
    #             log.error(f"ICKEY validation failed: {ic_keys}")
    #         return {"success": False, "error": msg}

    #     timings["prepare_keys"] = time.time() - t0
    #     t1 = time.time()

    #     reader = HFReaderDLLInterface(ip_address, port)

    #     try:
    #         # 1) Conexión inicial y lectura de UID
    #         com_addr, frm_handle, uid_hex = reader.connect(ip_address, port)
    #         if com_addr is None or frm_handle is None:
    #             raise RuntimeError("No se pudo conectar al lector en el arranque.")
    #         # LOG_INFO eliminado - logging directo
    #             log.info(f"Early UID read: {uid_hex}")
    #         reader.com_addr = com_addr
    #         reader.frm_handle = frm_handle

    #         timings["dll_instance"] = time.time() - t1
    #         t2 = time.time()

    #         results = {}
    #         processed_sectors = set()

    #         # 2) Iterar sobre cada bloque que queremos escribir
    #         for blk_str, hex_str in write_data.items():
    #             block_start = time.time()
    #             try:
    #                 block_num = int(blk_str)
    #             except ValueError:
    #                 results[blk_str] = "INVALID_BLOCK_NUMBER"
    #                 continue

    #             sector = block_num // 4

    #             # 2a) Nunca tocamos sector 0
    #             if sector == 0:
    #                 # LOG_INFO eliminado - logging directo
    #                 log.info(f"Skipping block {block_num} in sector 0")
    #                 continue

    #             # 2b) Validación de datos
    #             if not (isinstance(hex_str, str) and len(hex_str) == 32 and Utils.is_hexadecimal(hex_str)):
    #                 # LOG_ERROR eliminado - logging directo
    #                 log.error(f"Invalid data for block {blk_str}: {hex_str}")
    #                 results[blk_str] = "INVALID_DATA"
    #                 continue

    #             # 3) Autenticación por sector (solo la primera vez)
    #             if sector not in processed_sectors:
    #                 try:
    #                     reader.disconnect()
    #                 except Exception:
    #                     pass  # si falla al desconectar, seguimos de todos modos

    #                 # Reconectamos al lector para arrancar una sesión nueva
    #                 com_addr, frm_handle, uid_hex_tmp = reader.connect(ip_address, port)
    #                 if com_addr is None or frm_handle is None:
    #                     # LOG_ERROR eliminado - logging directo
    #                     log.error(f"Error al reconectar para sector {sector}")
    #                     results[blk_str] = "READ_CONECT_FAIL"
    #                     continue
    #                 reader.com_addr = com_addr
    #                 reader.frm_handle = frm_handle
    #                 uid_hex = uid_hex or uid_hex_tmp

    #                 # LOG_INFO eliminado - logging directo
    #                 log.info(f"Authenticating sector {sector} with keys {ic_keys}")
    #                 sec_res = reader.open_sector(ip_address, port, sector, ic_keys)
    #                 if not (isinstance(sec_res, tuple) and len(sec_res) == 5):
    #                     results[blk_str] = "SECTOR_AUTH_ERROR"
    #                     continue

    #                 com_addr, frm_handle, uid_tmp2, auth_ok, _key_hex = sec_res
    #                 if not auth_ok:
    #                     # LOG_WARNING eliminado - logging directo
    #                     log.warning(f"Sector {sector}: auth failed.")
    #                     results[blk_str] = "AUTH_FAIL"
    #                     continue

    #                 # Guardamos el handle válido para las escrituras de este sector
    #                 reader.com_addr = com_addr
    #                 reader.frm_handle = frm_handle
    #                 uid_hex = uid_hex or uid_tmp2
    #                 processed_sectors.add(sector)

    #             # 4) Escritura del bloque
    #             write_ok = reader.iso14443a_write(reader.com_addr, block_num, hex_str, reader.frm_handle)
    #             if write_ok:
    #             log.info(f"Block {block_num} written: {hex_str}")
    #                 results[blk_str] = hex_str
    #             else:
    #                 # LOG_WARNING eliminado - logging directo
    #                 log.warning(f"Block {block_num} write failed.")
    #                 results[blk_str] = "WRITE_FAIL"

    #             timings[f"block_{block_num}_write"] = time.time() - block_start

    #         timings["data_blocks"] = time.time() - t2
    #         timings["total"] = time.time() - t0

    #         log.info(f"⏱ Detailed timings: {json.dumps(timings, indent=2)}")

    #         # 5) Resultado global
    #         failed = [v for v in results.values()
    #                 if v in ("INVALID_DATA", "SECTOR_AUTH_ERROR", "AUTH_FAIL", "WRITE_FAIL")]
    #         success = len(failed) == 0
    #         return {"success": success, "blocks": results, "uid": uid_hex, "timings": timings}

    #     except Exception as e:
    #         # LOG_ERROR eliminado - logging directo
    #             log.error(f"Critical exception in _write_card_data: {e}")
    #         return {"success": False, "error": str(e)}

    #     finally:
    #         try:
    #             reader.disconnect()
    #             # LOG_INFO eliminado - logging directo
    #             log.info("Reader disconnected cleanly.")
    #         except Exception:
    #             pass
    
    def _write_card_data(self, ip_address: str, port: int, write_data: dict, ic_keys=None) -> dict:
        # LOG_INFO eliminado - logging directo
        log.info("Entering _write_card_data")
        log.info(f"ICKEY state at _write_card_data start: {ic_keys}")

        timings = {}
        t0 = time.time()

        # 0) Normalizar ic_keys
        if isinstance(ic_keys, str):
            # LOG_INFO eliminado - logging directo
            log.info(f"Converting single ICKEY string to list: {ic_keys}")
            ic_keys = [ic_keys.strip()]
        if not ic_keys or any(not isinstance(k, str) or not Utils.is_hexadecimal(k) for k in ic_keys):
            msg = "IC key inválida o no proporcionada: se necesita al menos una para autenticar sectores."
            # LOG_ERROR eliminado - logging directo
            log.error(f"ICKEY validation failed: {ic_keys}")
            return {"success": False, "error": msg}

        timings["prepare_keys"] = time.time() - t0
        t1 = time.time()

        reader = HFReaderDLLInterface(ip_address, port)

        try:
            # 1) Instancia del reader sin leer UID inicialmente
            timings["dll_instance"] = time.time() - t1
            t2 = time.time()

            results = {}
            processed_sectors = set()
            uid_hex = None

            # 2) Iterar sobre cada bloque que queremos escribir
            for blk_str, hex_str in write_data.items():
                block_start = time.time()
                try:
                    block_num = int(blk_str)
                except ValueError:
                    results[blk_str] = "INVALID_BLOCK_NUMBER"
                    continue

                sector = block_num // 4

                # 2a) Nunca tocamos sector 0
                if sector == 0:
                    # LOG_INFO eliminado - logging directo
                    log.info(f"Skipping block {block_num} in sector 0")
                    continue

                # 2b) Validación de datos
                if not (isinstance(hex_str, str) and len(hex_str) == 32 and Utils.is_hexadecimal(hex_str)):
                    # LOG_ERROR eliminado - logging directo
                    log.error(f"Invalid data for block {blk_str}: {hex_str}")
                    results[blk_str] = "INVALID_DATA"
                    continue

                # 3) Autenticación por sector (solo la primera vez)
                if sector not in processed_sectors:
                    # >>> Desconectar y reconectar para "limpiar" la ICKEY
                    try:
                        reader.disconnect()
                    except Exception:
                        pass  # Si falla al desconectar, seguimos

                    com_addr, frm_handle, uid_hex_tmp = reader.connect(ip_address, port)
                    if com_addr is None or frm_handle is None:
                        # LOG_ERROR eliminado - logging directo
                        log.error(f"Error al reconectar para sector {sector}")
                        results[blk_str] = "READ_CONECT_FAIL"
                        continue
                    reader.com_addr = com_addr
                    reader.frm_handle = frm_handle
                    uid_hex = uid_hex or uid_hex_tmp

                    # LOG_INFO eliminado - logging directo
                    log.info(f"Authenticating sector {sector} with keys {ic_keys}")
                    sec_res = reader.open_sector(ip_address, port, sector, ic_keys)
                    if not (isinstance(sec_res, tuple) and len(sec_res) == 5):
                        results[blk_str] = "SECTOR_AUTH_ERROR"
                        continue

                    com_addr, frm_handle, uid_tmp2, auth_ok, _key_hex = sec_res
                    if not auth_ok:
                        # LOG_WARNING eliminado - logging directo
                        log.warning(f"Sector {sector}: auth failed.")
                        results[blk_str] = "AUTH_FAIL"
                        continue

                    # Guardamos el handle válido para las escrituras de este sector
                    reader.com_addr = com_addr
                    reader.frm_handle = frm_handle
                    uid_hex = uid_hex or uid_tmp2
                    processed_sectors.add(sector)

                # 4) Escritura del bloque
                write_ok = reader.iso14443a_write(reader.com_addr, block_num, hex_str, reader.frm_handle)
                if write_ok:
                    # LOG_INFO eliminado - logging directo
                    log.info(f"Block {block_num} written: {hex_str}")
                    results[blk_str] = hex_str
                else:
                    # LOG_WARNING eliminado - logging directo
                    log.warning(f"Block {block_num} write failed.")
                    results[blk_str] = "WRITE_FAIL"

                timings[f"block_{block_num}_write"] = time.time() - block_start

            timings["data_blocks"] = time.time() - t2
            timings["total"] = time.time() - t0

            log.info(f"⏱ Detailed timings: {json.dumps(timings, indent=2)}")

            # 5) Resultado global
            failed = [
                v for v in results.values()
                if v in ("INVALID_DATA", "SECTOR_AUTH_ERROR", "AUTH_FAIL", "WRITE_FAIL")
            ]
            success = len(failed) == 0
            return {"success": success, "blocks": results, "uid": uid_hex, "timings": timings}

        except Exception as e:
            # LOG_ERROR eliminado - logging directo
            log.error(f"Critical exception in _write_card_data: {e}")
            return {"success": False, "error": str(e)}

        finally:
            try:
                reader.disconnect()
                # LOG_INFO eliminado - logging directo
                log.info("Reader disconnected cleanly.")
            except Exception:
                pass

    
    @serialize_by_ip_and_port(get_ip_arg_index=1, get_port_arg_index=2)
    def write_reset_data(self, ip_address: str, port: int, decrypted_ic_key_hex: Optional[str] = None) -> Dict[str, Union[bool, str]]:
        """
        Writes zeros to all sectors (except sector 0) to reset the card.
        """
        
        start_time = time.time()
        response_data = {}

        # LOG_INFO eliminado - logging directo
        log.info("Starting card reset operation...")

        # Use new connection method (instead of prepare_reader)
        reader = HFReaderDLLInterface(ip_address,port)
        com_addr, frm_handle, uid_hex = reader.connect(ip_address, port)
        
        if com_addr is None or frm_handle is None:
            # LOG_ERROR eliminado - logging directo
            log.error("Failed to establish connection.")
            return {"success": False, "error": "Failed to establish connection."}

        # LOG_INFO eliminado - logging directo
        log.info(f"Card UID: {uid_hex}")

        processed_sectors = set()

        # Iterate through sectors (excluding sector 0)
        for sector_number in range(1, 16):
            # LOG_INFO eliminado - logging directo
            log.info(f"Authenticating sector {sector_number}...")

            # open_sector ya maneja el fallback: PRIMERO la key del hotel, DESPUÉS FFFFFFFFFFFF
            keys_to_try = [decrypted_ic_key_hex] if decrypted_ic_key_hex else None
            
            # Fix: Correct unpacking of `open_sector` return values
            com_addr, frm_handle, uid_hex, auth_result, key_hex = reader.open_sector(ip_address, port, sector_number, keys_to_try)

            if not auth_result:
                # LOG_WARNING eliminado - logging directo
                log.warning(f"Sector {sector_number}: Authentication failed. Skipping sector.")
                continue  # Skip this sector if authentication fails

            processed_sectors.add(sector_number)

            # Step 1: Write zeroes to data blocks (except trailer block)
            for block_offset in range(3):  # Blocks 0, 1, and 2
                block_number = sector_number * 4 + block_offset
                zero_data = "00" * 16  # 16 bytes of zeroes

                result = reader.iso14443a_write(com_addr, block_number, zero_data, frm_handle)

                # Fix: iso14443a_write returns a string (written data), check `None`
                if result is not None:
                    # LOG_INFO eliminado - logging directo
                    log.info(f"Successfully reset block {block_number} to factory values: zeroes.")
                    response_data[str(block_number)] = "RESET_SUCCESS"
                else:
                    # LOG_WARNING eliminado - logging directo
                    log.warning(f"Failed to reset block {block_number}.")
                    response_data[str(block_number)] = "RESET_FAIL"

        # Step 2: Reset trailer blocks to factory settings
        for sector_number in processed_sectors:
            trailer_block = sector_number * 4 + 3  # Trailer block position
            # LOG_INFO eliminado - logging directo
            log.info(f"Resetting trailer block {trailer_block} to factory defaults...")

            # Fix: Correct factory trailer block (Key A, Access Bits, User Data, Key B)
            factory_key = "FFFFFFFFFFFF"
            access_bits = "078069"  # Correct factory default access bits
            user_data = "FF"  # Default user byte (some systems use FF)
            trailer_data = factory_key + access_bits + user_data + factory_key  # Full 16 bytes

            result = reader.iso14443a_write(com_addr, trailer_block, trailer_data, frm_handle)

            if result is not None:
                # LOG_INFO eliminado - logging directo
                log.info(f"Successfully reset sector {sector_number} trailer block.")
                response_data[str(trailer_block)] = "RESET_SUCCESS"
            else:
                # LOG_WARNING eliminado - logging directo
                log.warning(f"Failed to reset trailer block {trailer_block}.")
                response_data[str(trailer_block)] = "RESET_FAIL"

        # LOG_INFO eliminado - logging directo
            log.info("Factory reset completed.")

        reader.disconnect()  # Ensure proper cleanup

        if any(status == "RESET_FAIL" for status in response_data.values()):
            return {"success": False, "details": response_data}
        else:
            return {"success": True, "details": response_data, "uid": uid_hex}
        
    @serialize_by_ip_and_port(get_ip_arg_index=2, get_port_arg_index=3)
    def revalidate_card_workflow(self, card_uid_hex: str, ip_address: str, port: int):
        from django.apps import apps
        DeviceRegistry      = apps.get_model('device_registry', 'DeviceRegistry')
        InstanceCredentials = apps.get_model('device_registry', 'InstanceCredentials')

        try:
            # 1) Convert hex UID to decimal
            card_uid_dec = str(int(card_uid_hex, 16))
            # LOG_INFO eliminado - logging directo
            log.info(f"Starting revalidation workflow for UID: {card_uid_hex}")

            # 2) Lookup device → instance
            device = DeviceRegistry.objects.filter(ip=ip_address, port=port).first()
            if not device or not device.instance:
                # LOG_ERROR eliminado - logging directo
                log.error(f"No device with IP {ip_address} and port {port} found, or instance is missing.")
                return
            instance_name = device.instance

            # 3) Fetch & decrypt credentials
            try:
                creds = InstanceCredentials.objects.get(instance=instance_name)
                username = creds.username
                password = creds.password
                # LOG_INFO eliminado - logging directo
                log.info(f"Decrypted credentials for instance '{instance_name}'")
            except InstanceCredentials.DoesNotExist:
                # LOG_ERROR eliminado - logging directo   
                log.error(f"No credentials found for instance '{instance_name}'")
                return

            # 4) Call revalidation endpoint directly, but inject the full Cookie header
            backend_domain = "osaccess-backend.osaccess.net"
            reval_url = f"https://{backend_domain}/api/Revalidadores/revalidar"

            reval_payload = {
                "user":     username,
                "password": password,
                "uid":      card_uid_dec
            }
            reval_headers = {
                "Content-Type": "application/json",
                "Accept":        "application/json",
                "User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                 "AppleWebKit/537.36 (KHTML, like Gecko) "
                                 "Chrome/135.0.0.0 Safari/537.36",
                "instance":      instance_name,
            }

            # Log and fire
            # LOG_INFO eliminado - logging directo
            log.info(f"Request URL: {reval_url}")
            log.info(f"Request Headers: {json.dumps(reval_headers, indent=4)}")
            log.info(f"Request Body: {json.dumps(reval_payload, indent=4)}")
            log.info(f"→ POST {reval_url} instance={instance_name}")

            reval_resp = requests.post(
            reval_url,
            headers=reval_headers,
            json=reval_payload,
            timeout=10
            )

            try:
                reval_resp.raise_for_status()
            except requests.exceptions.HTTPError as err:
                # LOG_ERROR eliminado - logging directo
                log.error(f"Revalidar falló: {reval_resp.status_code} {reval_resp.text}")
                return {
                    "success": False,
                    "error": f"{reval_resp.status_code}: {reval_resp.text}"
                }

            osaccess_data = reval_resp.json()

            # LOG_INFO eliminado - logging directo
            log.info("OSACCESS response:")
            log.info(json.dumps(osaccess_data, indent=4))

            # 5) Generate sector data and write
            parametros = osaccess_data.get("parametros")
            if not parametros or "hotelInfo" not in parametros:
                # LOG_ERROR eliminado - logging directo
                log.error("OSACCESS revalidation response missing required data.")
                return

            whitelist_data, blacklist_data = Utils.transform_data_for_revalidate(osaccess_data)
            hotel_info = parametros["hotelInfo"]
            
            sector_data = CardEncoderDLLService().generate_card_data(
                hotel_info=hotel_info,
                card_uid=card_uid_hex,
                whitelist_data=whitelist_data,
                blacklist_data=blacklist_data
            )
            if not sector_data:
                # LOG_ERROR eliminado - logging directo
                log.error("Failed to generate sector data.")
                return
            
            ic_key = OmnitecCrypto.decrypt(parametros.get("icKey"))
            if not ic_key or not Utils.is_hexadecimal(ic_key):
                # LOG_ERROR eliminado - logging directo
                log.error(f"Invalid or missing ICKEY in OSACCESS response: {ic_key!r}")
                return {"success": False, "error": "Invalid or missing icKey"}
            
            # LOG_INFO eliminado - logging directo
            log.info(f"ICKEY decrypted from OSACCESS: {ic_key}")
            log.info(f"Using ICKEY for card write: {ic_key}")

            write_result = self._write_card_data(ip_address, port, sector_data, ic_keys=[ic_key])
            
            block_results = write_result.get("blocks", {})
            failed_blocks = [
                v for v in block_results.values()
                if v in ["WRITE_FAIL","ERROR","INVALID_DATA"]
            ]
            return {
                "success": len(failed_blocks) == 0,
                "blocks":  block_results,
                "error":   "Some blocks failed to write" if failed_blocks else None,
                "uid":     card_uid_hex
            }   
        except Exception as e:
            # LOG_ERROR eliminado - logging directo
            log.error(f"Revalidation workflow error for UID {card_uid_hex}: {e}")

