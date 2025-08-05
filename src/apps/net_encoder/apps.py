import threading, time, sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
from django.apps import AppConfig
from src.lib.hf_reader_dll.hf_reader_dll_utils import HFReaderDLLUtils
from src.lib.hf_reader_dll.hf_reader_dll_service import HFReaderDLLService
from src.lib.utils.logger import Logger
# Logging ahora usa Python logging nativo

class NetEncoderConfig(AppConfig):
    name = 'apps.net_encoder'
    