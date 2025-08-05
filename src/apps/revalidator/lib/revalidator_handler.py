import time, threading
from src.lib.utils.logger import Logger
# Logging ahora usa Python logging nativo

class RevalidatorHandler:
    
    _quarantine_lock = threading.Lock()
    _quarantine_registry = {}  # (ip, port, uid_hex) → expire_timestamp
    _success_quarantine_duration = 30  # seconds

    @classmethod
    def is_in_quarantine(cls, ip, port, uid):
        key = (ip, port, uid)
        now = time.time()
        with cls._quarantine_lock:
            expire_time = cls._quarantine_registry.get(key)
            if expire_time and expire_time > now:
                return True
            # 🧹 Clean up expired entries
            cls._quarantine_registry = {
                k: v for k, v in cls._quarantine_registry.items() if v > now
            }
            return False

    @classmethod
    def add_to_quarantine(cls, ip, port, uid):
        key = (ip, port, uid)
        expire_time = time.time() + cls._success_quarantine_duration
        with cls._quarantine_lock:
            cls._quarantine_registry[key] = expire_time
        log.info(f"🚧 UID {uid} on {ip}:{port} added to quarantine until {expire_time}.")
