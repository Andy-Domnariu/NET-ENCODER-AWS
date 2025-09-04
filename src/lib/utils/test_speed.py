# # test_speed.py
# import sys
# import os
# import time
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
# from src.lib.hf_reader_dll.hf_threadmanager import serialize_by_ip_and_port
# from src.lib.hf_reader_dll.hf_reader_dll_interface import HFReaderDLLInterface
# from src.lib.utils.logger import Logger

# log = Logger("TEST_SERIALIZED")


# class TestRunner:
#     @serialize_by_ip_and_port(get_ip_arg_index=0, get_port_arg_index=1)
#     def run(self, ip, port):
#         start = time.time()
#         for i in range(10):
#             try:
#                 conn_start = time.time()
#                 reader = HFReaderDLLInterface(ip, port)
#                 reader.disconnect()
#                 reader.connect(ip, port)
#                 reader.disconnect()
#                 conn_time = time.time() - conn_start
#                 log.info(f"Iteration {i+1}: connect/disconnect took {conn_time:.3f}s")
#             except Exception as e:
#                 log.error(f"Connection test failed on iteration {i+1}: {e}")
#             time.sleep(0.1)  # simulate a small delay
#         end = time.time()
#         log.info(f"🔁 10 connections took {end - start:.2f}s (including ~1.0s intentional delay)")

# if __name__ == "__main__":
#     runner = TestRunner()
#     runner.run("88.30.56.6", 6000)

import socket
import urllib.request
import json
import ssl

API_URL = "http://15.236.16.120:8000/device/register/"
DB_HOST = "net-encoder.ceixe7g3ka27.eu-west-3.rds.amazonaws.com"
DB_PORT = 5432
TEST_MAC = "00AABBCCDDEE"
API_KEY = "PUy1Io8GIy7bNBHhH1NH8Nqcn23O17PHcDHa3nqKcqH83FPNylNrqCcJ8dIm75U3UUUaU9UlBUfnUVUhff"

def test_db_connection():
    print(f"🔌 Probando conexión TCP a PostgreSQL ({DB_HOST}:{DB_PORT})...")
    try:
        sock = socket.create_connection((DB_HOST, DB_PORT), timeout=5)
        sock.close()
        print("✅ Conexión al puerto 5432 OK (la DB responde a nivel de red).")
    except Exception as e:
        print(f"❌ Error conectando a DB:\n   {e}")

def test_api_connection():
    print(f"\n🌍 Probando API POST a {API_URL}...")
    payload = json.dumps({"mac": TEST_MAC}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-API-KEY": API_KEY
    }
    req = urllib.request.Request(API_URL, data=payload, headers=headers)

    try:
        context = ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=5) as response:
            result = response.read().decode()
            print("✅ Respuesta de la API:")
            print(result)
    except Exception as e:
        print(f"❌ Error al conectar con la API:\n   {e}")

if __name__ == "__main__":
    print("🧪 Iniciando test de red y API...\n")
    test_db_connection()
    test_api_connection()
    print("\n🚀 Fin del test. Pásale esto a Andy o pégalo en el chat.")
