from queue import Queue
import threading
import time
from typing import Callable, Dict
from src.lib.hf_reader_dll.hf_threadsafe import HFReaderDLLThreadSafe



class HFReaderDLLManager:
    _instances: Dict[str, HFReaderDLLThreadSafe] = {}
    _queues: Dict[str, Queue] = {}
    _locks: Dict[str, threading.Lock] = {}
    _lock = threading.Lock()

    @classmethod
    def get_for_ip(cls, ip: str, port: int) -> HFReaderDLLThreadSafe:
        key = f"{ip}:{port}"
        with cls._lock:
            if key not in cls._instances:
                cls._instances[key] = HFReaderDLLThreadSafe(ip, port)
            return cls._instances[key]

    @classmethod
    def run_serialized(cls, ip: str, port: int, func: Callable, *args, **kwargs):
        key = f"{ip}:{port}"
        with cls._lock:
            if key not in cls._queues:
                cls._queues[key] = Queue()
                cls._locks[key] = threading.Lock()
                threading.Thread(target=cls._process_queue, args=(key,), daemon=True).start()
            cls._queues[key].put((func, args, kwargs))
            print(f"🟡 [{key}] Task enqueued: {func.__name__}")

    @classmethod
    def _process_queue(cls, key: str):
        queue = cls._queues[key]
        while True:
            func, args, kwargs = queue.get()
            with cls._locks[key]:
                try:
                    func(*args, **kwargs)
                except Exception as e:
                    print(f"Exception in high-level queue for {key}: {e}")

def serialize_by_ip_and_port(get_ip_arg_index: int = 0, get_port_arg_index: int = 1):
    def decorator(func):
        def wrapper(*args, **kwargs):
            ip = args[get_ip_arg_index]
            port = args[get_port_arg_index]
            result_container = {}

            def job():
                result_container["result"] = func(*args, **kwargs)

            HFReaderDLLManager.run_serialized(ip, port, job)

            while "result" not in result_container:
                time.sleep(0.01)

            return result_container["result"]
        return wrapper
    return decorator