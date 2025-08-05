NET Card Encoder Project

Este repositorio contiene la aplicación Django NET Card Encoder, que integra:

Lectura y escritura de tarjetas Mifare 1K vía lector HF (HFReader.dll)

Generación de datos de sector usando CardEncoder.dll

Endpoints REST para gestión de dispositivos y revalidación automática

Requisitos previos

Sistema operativo: Windows (por la dependencia de los DLLs), también probado en Linux con Wine.

Python: versión 3.10 o superior.

Git: para clonar el repositorio.

DLLs:

dll/CardEncoder.dll

dll/HFReader.dll
Deben estar presentes en la carpeta src/lib/card_encoder_dll/dll y src/lib/hf_reader_dll respectivamente.

Base de datos: SQLite (por defecto) o PostgreSQL/MySQL si prefieres.

Pasos para poner en marcha el proyecto

Clonar el repositorio

git clone https://github.com/<tu_usuario>/<tu_repositorio>.git
cd <tu_repositorio>

Crear y activar un entorno virtual

python -m venv venv
# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate

Actualizar pip e instalar dependencias

pip install --upgrade pip
pip install -r requirements.txt

Configurar variables de entorno

Crea un archivo .env en la raíz del proyecto con al menos estas variables:

# Django
SECRET_KEY="tu_secret_key_django"
DEBUG=True
ALLOWED_HOSTS=127.0.0.1,localhost

# API Keys
NET_ENCODER_API_KEY="tu_api_key_principal"
COLLEAGUE_API_KEY="tu_api_key_colleague"

# Base de datos (si no usas SQLite)
DB_NAME="nombre_bd"
DB_USER="usuario_bd"
DB_PASSWORD="password_bd"
DB_HOST="localhost"
DB_PORT=5432

Nota: Ajusta config/settings.py para leer estas variables usando python-decouple o django-environ, si aún no está configurado.

Aplicar migraciones y crear superusuario

python manage.py migrate
python manage.py createsuperuser

(Opcional) Recolectar archivos estáticos

python manage.py collectstatic --noinput

Ejecutar servidor de desarrollo

python manage.py runserver

Accede luego a http://127.0.0.1:8000/.

Uso de la API

Registro de dispositivos: POST /device/register/ con { "mac": "001122AABBCC" }

Lectura/escritura de tarjeta: POST /card/read/, POST /card/write/ (requiere NET_ENCODER_API_KEY)

Pinging: GET /device/ping/

Consulta la carpeta src/apps para más detalles de los endpoints.

Notas finales

Asegúrate de que los DLLs están en las rutas correctas.

