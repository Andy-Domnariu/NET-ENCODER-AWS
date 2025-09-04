import re
from src.lib.utils.logger import get_logger
from ctypes import c_void_p

logger = get_logger("mac_normalizer")

comodín = "000000000000"

def convert_mac_for_dll(mac):
    """
    Convierte MAC para DLL con manejo robusto de casos "sin restricción".
    
    Casos "sin restricción" (NULL a la DLL):
    - None
    - 0 (int/float)
    - "0" (string)
    
    Casos "MAC normal" (normalización estándar):
    - Strings con formato MAC válido
    
    Otros casos: ValueError
    """
    # Caso 1: sin restricción -> NULL a la DLL
    if mac is None:
        logger.info("MAC es None -> c_void_p(0) (sin restricción)")
        return c_void_p(0)
    if isinstance(mac, (int, float)) and int(mac) == 0:
        logger.info("MAC es 0 (numérico) -> c_void_p(0) (sin restricción)")
        return c_void_p(0)
    if isinstance(mac, str) and mac.strip() == "0":
        logger.info("MAC es '0' (string) -> c_void_p(0) (sin restricción)")
        return c_void_p(0)

    # Caso 2: MAC "normal" (string) -> normaliza como antes
    if isinstance(mac, str):
        # Usar la lógica de normalización existente
        try:
            normalized = normalize_mac_or_comodín_nullish(mac)
            logger.info(f"MAC normalizada: {mac!r} -> {normalized}")
            return normalized
        except ValueError as e:
            raise ValueError(f"MAC inválida: {mac}")

    # Otros tipos no válidos
    raise ValueError(f"Tipo de MAC no soportado: {type(mac).__name__}")

def _strip_mac(s: str) -> str:
    """Limpia y extrae solo caracteres hexadecimales de una MAC."""
    s = s.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    return re.sub(r"[^0-9A-Fa-f]", "", s)

def normalize_mac_or_comodín_nullish(mac) -> str:
    """
    Contrato estricto:
    - None/0/'00:..:00' -> comodín
    - MAC válida -> 12 hex uppercase
    - Cualquier otra cosa -> ValueError (NO comodín)
    """
    if mac is None:
        return comodín
    if isinstance(mac, int):
        return comodín if mac == 0 else f"{mac:012X}"

    s = str(mac).strip()
    if not s:
        raise ValueError("MAC vacía")
    
    # Casos especiales de comodín
    if s == "0" or s == "00:00:00:00:00:00":
        return comodín

    # Validar formatos específicos antes de limpiar
    # Formato con dos puntos: AA:BB:CC:DD:EE:FF
    if re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', s):
        result = s.replace(":", "").upper()
        if int(result, 16) == 0:
            return comodín
        return result
    
    # Formato con guiones: AA-BB-CC-DD-EE-FF
    if re.match(r'^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$', s):
        result = s.replace("-", "").upper()
        if int(result, 16) == 0:
            return comodín
        return result
    
    # Formato con 0x: 0xAABBCCDDEEFF
    if re.match(r'^0x[0-9A-Fa-f]+$', s):
        hex_value = s[2:]
        if len(hex_value) < 12:
            hex_value = hex_value.zfill(12)
        elif len(hex_value) > 12:
            hex_value = hex_value[-12:]
        if int(hex_value, 16) == 0:
            return comodín
        return hex_value.upper()
    
    # Formato continuo: AABBCCDDEEFF (exactamente 12 caracteres)
    if re.match(r'^[0-9A-Fa-f]{12}$', s):
        if int(s, 16) == 0:
            return comodín
        return s.upper()
    
    # Si no coincide con ningún formato específico, es inválido
    raise ValueError(f"MAC inválida: {mac}")

# Función de compatibilidad para mantener el contrato anterior
def normalize_mac(mac) -> str:
    """
    Función de compatibilidad que mantiene el contrato anterior.
    Usar normalize_mac_or_comodín_nullish() para el nuevo contrato estricto.
    """
    try:
        return normalize_mac_or_comodín_nullish(mac)
    except ValueError:
        logger.warning(f"MAC inválida tratada como comodín: {mac}")
        return comodín
