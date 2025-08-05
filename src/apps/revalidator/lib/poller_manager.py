import threading
from src.lib.hf_reader_dll.hf_reader_dll_utils import HFReaderDLLUtils

class PollerManager:
    _pollers: dict[tuple[str,int], tuple[threading.Thread, threading.Event]] = {}

    @classmethod
    def start(cls, ip: str, port: int, sleep: float = 1.0) -> bool:
        key = (ip, port)
        # already running?
        if key in cls._pollers and cls._pollers[key][0].is_alive():
            return False

        stop_event = threading.Event()
        t = threading.Thread(
            target=HFReaderDLLUtils.start_polling,
            args=(ip, port, sleep, stop_event),
            daemon=True
        )
        cls._pollers[key] = (t, stop_event)
        t.start()
        return True

    @classmethod
    def stop(cls, ip: str, port: int) -> bool:
        key = (ip, port)
        entry = cls._pollers.get(key)
        if not entry:
            return False
        thread, ev = entry
        ev.set()            # signal loop to break
        thread.join(5)      # wait up to 5s
        cls._pollers.pop(key, None)
        return True
