import sys, os, ctypes
# import psutil  # Comentado temporalmente
import threading
import multiprocessing

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
from ctypes import c_long, c_ubyte, c_char_p, POINTER, byref
from typing import Tuple, Dict
from src.lib.utils.logger import Logger
from multiprocessing.connection import Connection 

log = Logger("hf_reader_dll_interface")

def _reader_process(pipe: Connection, dll_path: str):
    class ReaderProcess:
        def __init__(self, dll_path):
            self._dll = ctypes.CDLL(dll_path)
            self._define_signatures()

        def _define_signatures(self):
            self._dll.OpenNetPort.argtypes = [c_long, c_char_p, POINTER(c_ubyte), POINTER(c_long)]
            self._dll.OpenNetPort.restype = c_long

            self._dll.CloseNetPort.argtypes = [c_long]
            self._dll.CloseNetPort.restype = c_long

            self._dll.OpenRf.argtypes = [POINTER(c_ubyte), c_long]
            self._dll.OpenRf.restype = c_long

            self._dll.CloseRf.argtypes = [POINTER(c_ubyte), c_long]
            self._dll.CloseRf.restype = c_long

            self._dll.ChangeTo14443A.argtypes = [POINTER(c_ubyte), c_long]
            self._dll.ChangeTo14443A.restype = c_long

            self._dll.ISO14443ARequest.argtypes = [POINTER(c_ubyte), c_ubyte, POINTER(c_ubyte), POINTER(c_ubyte), c_long]
            self._dll.ISO14443ARequest.restype = c_long

            self._dll.ISO14443AAnticoll.argtypes = [POINTER(c_ubyte), c_ubyte, POINTER(c_ubyte), POINTER(c_ubyte), c_long]
            self._dll.ISO14443AAnticoll.restype = c_long

            self._dll.ISO14443ASelect.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte), POINTER(c_ubyte), c_long]
            self._dll.ISO14443ASelect.restype = c_long

            self._dll.ISO14443AAuthKey.argtypes = [POINTER(c_ubyte), c_ubyte, c_ubyte, POINTER(c_ubyte), POINTER(c_ubyte), c_long]
            self._dll.ISO14443AAuthKey.restype = c_long

            self._dll.ISO14443ARead.argtypes = [POINTER(c_ubyte), c_ubyte, POINTER(c_ubyte), POINTER(c_ubyte), c_long]
            self._dll.ISO14443ARead.restype = c_long

            self._dll.ISO14443AWrite.argtypes = [POINTER(c_ubyte), c_ubyte, POINTER(c_ubyte), POINTER(c_ubyte), c_long]
            self._dll.ISO14443AWrite.restype = c_long

        def call(self, method_name: str, args: tuple):
            if method_name == "OpenNetPort":
                port, ip = args
                com_addr = c_ubyte()
                frm_handle = c_long()
                result = self._dll.OpenNetPort(c_long(port), c_char_p(ip.encode()), byref(com_addr), byref(frm_handle))
                return (result, com_addr.value, frm_handle.value)

            elif method_name == "CloseNetPort":
                (port,) = args
                return self._dll.CloseNetPort(c_long(port))

            elif method_name == "OpenRf":
                com_addr, frm_handle = args
                com_addr_c = c_ubyte(com_addr)
                return self._dll.OpenRf(byref(com_addr_c), c_long(frm_handle))

            elif method_name == "CloseRf":
                com_addr, frm_handle = args
                com_addr_c = c_ubyte(com_addr)
                return self._dll.CloseRf(byref(com_addr_c), c_long(frm_handle))

            elif method_name == "ChangeTo14443A":
                com_addr, frm_handle = args
                com_addr_c = c_ubyte(com_addr)
                return self._dll.ChangeTo14443A(byref(com_addr_c), c_long(frm_handle))

            elif method_name == "ISO14443ARequest":
                com_addr, mode, frm_handle = args
                com_addr_c = c_ubyte(com_addr)
                tag_type = (c_ubyte * 2)()
                error_code = c_ubyte()
                result = self._dll.ISO14443ARequest(byref(com_addr_c), c_ubyte(mode), tag_type, byref(error_code), c_long(frm_handle))
                return (result, error_code.value)

            elif method_name == "ISO14443AAnticoll":
                log.info(f"ISO14443AAnticoll called with args: {args}")
                com_addr, frm_handle = args
                com_addr_c = c_ubyte(com_addr)
                uid = (c_ubyte * 4)()
                error_code = c_ubyte()
                result = self._dll.ISO14443AAnticoll(byref(com_addr_c), c_ubyte(0), uid, byref(error_code), c_long(frm_handle))
                return (result, error_code.value, bytes(uid).hex())

            elif method_name == "ISO14443ASelect":
                com_addr, uid_hex, frm_handle = args
                uid_bytes = bytes.fromhex(uid_hex)
                com_addr_c = c_ubyte(com_addr)
                uid_array = (c_ubyte * 4)(*uid_bytes)
                size = c_ubyte()
                error_code = c_ubyte()
                result = self._dll.ISO14443ASelect(byref(com_addr_c), uid_array, byref(size), byref(error_code), c_long(frm_handle))
                return (result, error_code.value)

            elif method_name == "ISO14443AAuthKey":
                com_addr, mode, sector, key_hex, frm_handle = args
                key_bytes = bytes.fromhex(key_hex)
                com_addr_c = c_ubyte(com_addr)
                key_array = (c_ubyte * 6)(*key_bytes)
                error_code = c_ubyte()
                result = self._dll.ISO14443AAuthKey(byref(com_addr_c), c_ubyte(mode), c_ubyte(sector), key_array, byref(error_code), c_long(frm_handle))
                return (result, error_code.value)

            elif method_name == "ISO14443ARead":
                com_addr, block_num, frm_handle = args
                com_addr_c = c_ubyte(com_addr)
                recv_data = (c_ubyte * 16)()
                error_code = c_ubyte()
                result = self._dll.ISO14443ARead(
                    byref(com_addr_c),
                    c_ubyte(block_num),
                    recv_data,
                    byref(error_code),
                    c_long(frm_handle)
                )
                return (result, error_code.value, bytes(recv_data).hex())

            elif method_name == "ISO14443AWrite":
                com_addr, block_num, hex_str, frm_handle = args
                com_addr_c = c_ubyte(com_addr)
                send_data = (c_ubyte * 16).from_buffer_copy(bytes.fromhex(hex_str))
                data_len = c_ubyte(16)
                result = self._dll.ISO14443AWrite(byref(com_addr_c), c_ubyte(block_num), send_data, byref(data_len), c_long(frm_handle))
                return result == 0

            else:
                raise NotImplementedError(f"Unsupported method: {method_name}")

    reader = ReaderProcess(dll_path)

    while True:
        method_name, args, kwargs = pipe.recv()
        try:
            result = reader.call(method_name, args)
            pipe.send(("result", result))
        except Exception as e:
            pipe.send(("error", str(e)))

class HFReaderDLLThreadSafe:
    _processes: Dict[str, Tuple[multiprocessing.Process, Connection]] = {}
    _lock = threading.Lock()

    def __init__(self, ip: str, port: int, dll_path: str = "dll\\HFReader.dll"):
        self.key = f"{ip}:{port}"
        with HFReaderDLLThreadSafe._lock:
            if self.key not in HFReaderDLLThreadSafe._processes:
                parent_conn, child_conn = multiprocessing.Pipe()
                proc = multiprocessing.Process(target=_reader_process, args=(child_conn, dll_path), daemon=True)
                proc.start()
                HFReaderDLLThreadSafe._processes[self.key] = (proc, parent_conn)
        self._conn = HFReaderDLLThreadSafe._processes[self.key][1]

    def call(self, method_name: str, *args, **kwargs):
        self._conn.send((method_name, args, kwargs))
        msg_type, data = self._conn.recv()
        if msg_type == "result":
            return data
        else:
            raise RuntimeError(data)

    def __getattr__(self, item):
        return lambda *args, **kwargs: self.call(item, *args, **kwargs)

