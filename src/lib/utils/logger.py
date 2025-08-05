import logging
import sys


class CustomLogHandler(logging.Handler):
    """Handler personalizado que RESPETA niveles de logging"""
    
    def __init__(self, source="UNKNOWN"):
        super().__init__()
        self.source = source
        # Configurar nivel inicial CRITICAL
        self.setLevel(logging.CRITICAL)
        
    def emit(self, record):
        # SOLO imprimir si el nivel lo permite
        # El logging.Handler ya filtra automáticamente, pero doble verificación
        if record.levelno >= self.level:
            timestamp = self.format(record)
            print(f"{timestamp} [{self.source}] [{record.levelname}]  {record.getMessage()}")
        
        # Guardar en base de datos si existe (comentado para evitar dependencia de Django)
        # try:
        #     DBLogHandler.insert_log(record.levelname, self.source, record.getMessage())
        # except:
        #     pass  # Si falla la BD, no interrumpir el flujo

class Logger:
    """Logger que RESPETA la configuración global de logging"""
    
    def __init__(self, source="UNKNOWN"):
        self.source = source
        self.logger = logging.getLogger(f"revalidador.{source}")
        
        # Configurar el handler personalizado solo una vez
        if not self.logger.handlers:
            handler = CustomLogHandler(source)
            formatter = logging.Formatter('%(asctime)s')
            handler.setFormatter(formatter)
            
            # RESPETAR nivel del logger padre (revalidador)
            parent_logger = logging.getLogger("revalidador")
            current_level = parent_logger.level or logging.CRITICAL
            
            # Configurar nivel en ambos: logger y handler
            self.logger.setLevel(current_level)
            handler.setLevel(current_level)
            
            self.logger.addHandler(handler)
    
    def set_level(self, level):
        """Cambiar nivel de logging dinámicamente"""
        if isinstance(level, str):
            level = getattr(logging, level.upper())
        self.logger.setLevel(level)
    
    def info(self, message):
        self.logger.info(message)

    def warning(self, message):
        self.logger.warning(message)

    def error(self, message):
        self.logger.error(message)

    def debug(self, message):
        self.logger.debug(message)

# Configuración global de logging para toda la aplicación
def configure_global_logging(level='INFO'):
    """
    Configura el nivel de logging para toda la aplicación
    Niveles: DEBUG, INFO, WARNING, ERROR, CRITICAL
    """
    if isinstance(level, str):
        level = getattr(logging, level.upper())
    
    # Configurar logging root y revalidador
    logging.getLogger().setLevel(level)
    logging.getLogger('revalidador').setLevel(level)
    
    # Actualizar TODOS los loggers existentes
    for name, logger in logging.Logger.manager.loggerDict.items():
        if isinstance(logger, logging.Logger) and name.startswith('revalidador'):
            logger.setLevel(level)
            # También actualizar los handlers
            for handler in logger.handlers:
                handler.setLevel(level)
    
    # Configurar también el logging básico de Python
    logging.basicConfig(level=level, format='%(asctime)s [%(name)s] [%(levelname)s] %(message)s')

# Instancia global para usar fácilmente
def get_logger(source="UNKNOWN"):
    """Factory function para crear loggers consistentes"""
    return Logger(source)
