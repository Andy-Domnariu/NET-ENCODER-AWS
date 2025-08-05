
import sys,os, time, threading
from src.apps.revalidator.lib.revalidator_handler import RevalidatorHandler
from src.lib.hf_reader_dll.hf_threadmanager import serialize_by_ip_and_port
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
from typing import Dict, Any, Optional
from src.lib.hf_reader_dll.hf_reader_dll_interface import HFReaderDLLInterface
from src.lib.hf_reader_dll.hf_reader_dll_service import HFReaderDLLService
from src.lib.utils.logger import Logger

log = Logger("hf_reader_dll_utils")

class HFReaderDLLUtils:
    """
    Utility class for handling card encoding operations and managing
    the connection to the card reader.
    """
    current_encoder = None
    current_com_addr = None
    current_frm_handle = None

    @staticmethod
    def iso14443a_anticoll_dict(
        interface: HFReaderDLLInterface,
        com_addr: int,
        frm_handle: int
    ) -> dict:
        """
        Wrapper around iso14443a_anticoll to return a dict.
        On success:  {"success": True, "uid_hex": "..."}
        On failure (including “no card”): {"success": False, "error": "..."}
        """
        try:
            uid_hex = interface.iso14443a_anticoll(com_addr, frm_handle)
            return {"success": True, "uid_hex": uid_hex}
        except Exception as e:
            # LOG_ERROR eliminado - logging directo 
            log.error(f"ISO14443AAnticoll error (treated as no-card): {e}")
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def iso14443a_request_dict(
        interface: HFReaderDLLInterface,
        com_addr: int,
        mode: int,
        frm_handle: int
    ) -> dict:
        """
        Wrapper around iso14443a_request to return a dict result that
        can be used in polling loops. Treats any exception as “no card”,
        rather than blowing up the thread.

        Returns:
            {"success": True}
            {"success": False, "error": "..."} on failure or no-card
        """
        try:
            # if it doesn’t raise, the request succeeded
            interface.iso14443a_request(com_addr, mode, frm_handle)
            return {"success": True}
        except Exception as e:
            # treat any error as simply “no card detected” for polling
            # LOG_INFO eliminado - logging directo
            log.info(f"ISO14443ARequest error (treated as no-card): {e}")
            return {"success": False, "error": str(e)}

    @staticmethod
    @serialize_by_ip_and_port(get_ip_arg_index=0, get_port_arg_index=1)
    def _poll_cycle(ip_address: str, port: int) -> Optional[str]:
        """
        One open-RF-mode-request-anticoll-close cycle.
        Returns the card UID hex if found, else None.
        """
        reader = HFReaderDLLInterface(ip_address, port)
        com_addr, frm_handle = reader.open_net_port(port, ip_address)
        if com_addr is None or frm_handle is None:
            return None

        try:
            # ① Turn on RF
            reader.open_rf(com_addr, frm_handle)
            # ② Switch to ISO14443A
            reader.change_to_14443a(com_addr, frm_handle)

            # ③ Try a request
            req = HFReaderDLLUtils.iso14443a_request_dict(reader, com_addr, 0x00, frm_handle)
            if not req["success"]:
                return None

            # ④ Try anticollision
            antic = HFReaderDLLUtils.iso14443a_anticoll_dict(reader, com_addr, frm_handle)
            return antic["uid_hex"] if antic["success"] else None

        finally:
                    # always clean up RF **and** network port
                    try:
                        reader.close_rf(com_addr, frm_handle)
                    except Exception:
                        pass
                    try:
                        reader.close_net_port(frm_handle)
                    except Exception:
                        pass
    @staticmethod
    def start_polling(
            ip_address: str,
            port: int,
            sleep_seconds: float = 1.0,
            stop_event: threading.Event = None
        ) -> None:
            """
            Runs _poll_cycle() every sleep_seconds; fires revalidation on success.
            """
            # LOG_INFO eliminado - logging directo
            log.info(f"start_polling -> ip={ip_address}, port={port}, sleep_seconds={sleep_seconds}")
            card_present = False

            while True:
                if stop_event and stop_event.is_set():
                    # LOG_INFO eliminado - logging directo
                    log.info(f"Polling on {ip_address}:{port} stopped by request.")
                    break

                uid = HFReaderDLLUtils._poll_cycle(ip_address, port)

                if uid and not RevalidatorHandler.is_in_quarantine(ip_address, port, uid):
                    RevalidatorHandler.add_to_quarantine(ip_address, port, uid)
                    # LOG_INFO eliminado - logging directo
                    log.info(f"✅ Card detected: UID={uid}. Launching revalidation.")
                    threading.Thread(
                        target=HFReaderDLLService().revalidate_card_workflow,
                        args=(uid, ip_address, port),
                        daemon=True
                    ).start()
                    card_present = True

                else:
                    # Debounce card-removal
                    if card_present:
                        time.sleep(1)
                        card_present = False

                time.sleep(sleep_seconds)