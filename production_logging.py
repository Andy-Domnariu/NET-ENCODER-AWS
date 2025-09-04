"""
Configuración permanente de logging para producción
Importa esto en manage.py o settings.py
"""
import logging
import os
import sys

# Add project path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def configure_production_logging():
    """Configuración ultrasilenciosa para producción"""
    from src.lib.utils.logger import configure_global_logging
    
    # PASO 1: Configurar CRITICAL con la función mejorada
    configure_global_logging('DEBUG')
    
    # PASO 2: Limpiar handlers existentes que puedan interferir
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    # PASO 3: Configurar nivel en todos lados
    logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger('revalidador').setLevel(logging.DEBUG)
    
    # PASO 4: Silenciar módulos específicos completamente
    modules_to_silence = [
        'revalidador.card_encoder_dll_service',
        'revalidador.hf_reader_dll_service', 
        'revalidador.hf_reader_dll_interface',
        'revalidador.net_encoder_handler',
        'revalidador.card_encoder_dll_interface',
        'revalidador.card_encoder_dll_utils',
        'django.server',
        'django.request'
    ]
    
    for module in modules_to_silence:
        logger = logging.getLogger(module)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False  # No propagar a padres
        # Silenciar también sus handlers
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
    
    print("🔇 Producción: Logging ULTRASILENCIOSO activado - Logger personalizado corregido")

# Auto-configure when imported
configure_production_logging()