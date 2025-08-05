import sys
import os

# Define the base directory of the project.
BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")

# Add the src directory to the python path.
sys.path.insert(0, BASE_DIR)

# 🎯 CONFIGURACIÓN ULTRA-SILENCIOSA PARA PRODUCCIÓN
try:
    import production_logging  # Auto-configura logging al importar
except ImportError:
    print("⚠️ Configurando logging básico silencioso")
    import logging
    logging.basicConfig(level=logging.CRITICAL)
    logging.getLogger().setLevel(logging.CRITICAL)


def main():
    """Run administrative tasks."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
