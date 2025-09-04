

#-------------------------------------legacy------------------------------------
# import threading
# from src.lib.hf_reader_dll.hf_reader_dll_utils import HFReaderDLLUtils

# class PollerManager:
#     _pollers: dict[tuple[str,int], tuple[threading.Thread, threading.Event]] = {}
    # @classmethod
    # def start(cls, ip: str, port: int, sleep: float = 1.0) -> bool:
    #     key = (ip, port)
    #     # already running?
    #     if key in cls._pollers and cls._pollers[key][0].is_alive():
    #         return False

    #     stop_event = threading.Event()
    #     t = threading.Thread(
    #         target=HFReaderDLLUtils.start_polling,
    #         args=(ip, port, sleep, stop_event),
    #         daemon=True
    #     )
    #     cls._pollers[key] = (t, stop_event)
    #     t.start()
    #     return True

    # @classmethod
    # def stop(cls, ip: str, port: int) -> bool:
    #     key = (ip, port)
    #     entry = cls._pollers.get(key)
    #     if not entry:
    #         return False
    #     thread, ev = entry
    #     ev.set()            # signal loop to break
    #     thread.join(5)      # wait up to 5s
    #     cls._pollers.pop(key, None)
    #     return True
#-------------------------------------legacy------------------------------------
import threading, time
from typing import Dict, Tuple, Optional
from django.apps import apps
from src.apps.revalidator.lib.revalidator_handler import RevalidatorHandler
from src.lib.utils.logger import Logger
from src.lib.hf_reader_dll.hf_reader_dll_service import HFReaderDLLService
from src.lib.hf_reader_dll.hf_reader_dll_utils import HFReaderDLLUtils

log = Logger("poller_manager")

class PollerManager:
    _pollers: Dict[str, Tuple[threading.Thread, threading.Event]] = {}
    _lock = threading.Lock()

    @classmethod
    def _make_key(cls, ip: str, port: int) -> str:
        return f"{ip}:{port}"

    @classmethod
    def start_all_polling(cls, sleep_seconds: float = 1.0) -> None:
        """
        For every DeviceRegistry entry with is_revalidator=True,
        spin up one polling thread (if not already running).
        """
        DeviceRegistry = apps.get_model("device_registry", "DeviceRegistry")
        readers = DeviceRegistry.objects.filter(is_revalidator=True)

        with cls._lock:
            for dev in readers:
                if not dev.ip or not dev.port:
                    continue
                key = cls._make_key(dev.ip, dev.port)
                if key in cls._pollers:
                    continue  

                stop_event = threading.Event()
                t = threading.Thread(
                    target=HFReaderDLLUtils.start_polling,
                    args=(dev.ip, dev.port, sleep_seconds, stop_event),
                    daemon=True
                )
                cls._pollers[key] = (t, stop_event)
                t.start()
                log.info(f"Started polling for reader {key}")

    @classmethod
    def stop_all_polling(cls) -> None:
        """
        Signal all polling threads to stop, then clear the registry.
        """
        with cls._lock:
            for key, (thread, stop_event) in cls._pollers.items():
                stop_event.set()
                log.info(f"Signaled stop for polling {key}")
            cls._pollers.clear()

    @classmethod
    def _poll_loop(
        cls,
        ip_address: str,
        port: int,
        sleep_seconds: float,
        stop_event: threading.Event
    ) -> None:
        """
        The per-reader loop: every sleep_seconds, run one
        HFReaderDLLService._poll_cycle() and, on a new UID,
        kick off a revalidation thread (debounced via quarantine).
        """
        key = cls._make_key(ip_address, port)
        log.info(f"Poll loop starting for {key}")

        while not stop_event.is_set():
            uid: Optional[str] = HFReaderDLLUtils._poll_cycle(ip_address, port)

            if uid:
                if not RevalidatorHandler.is_in_quarantine(ip_address, port, uid):
                    RevalidatorHandler.add_to_quarantine(ip_address, port, uid)
                    log.info(f"Card detected on {key}: {uid!r}, launching revalidation")
                    threading.Thread(
                        target=HFReaderDLLService().revalidate_card_workflow,
                        args=(uid, ip_address, port),
                        daemon=True
                    ).start()

            time.sleep(sleep_seconds)

        log.info(f"Poll loop exiting for {key}")
