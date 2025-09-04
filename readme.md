# NET Card Encoder Project

Este repositorio contiene la aplicación Django NET Card Encoder, que integra:

- Lectura y escritura de tarjetas Mifare 1K vía lector HF (HFReader.dll)
- Generación de datos de sector usando CardEncoder.dll
- Endpoints REST para gestión de dispositivos y revalidación automática
- Sistema robusto de normalización de direcciones MAC

## Requisitos previos

- **Sistema operativo**: Windows (por la dependencia de los DLLs), también probado en Linux con Wine
- **Python**: versión 3.10 o superior
- **Git**: para clonar el repositorio
- **DLLs**:
  - `dll/CardEncoder.dll`
  - `dll/HFReader.dll`
  - Deben estar presentes en la carpeta `src/lib/card_encoder_dll/dll` y `src/lib/hf_reader_dll` respectivamente
- **Base de datos**: SQLite (por defecto) o PostgreSQL/MySQL si prefieres

## Pasos para poner en marcha el proyecto

### 1. Clonar el repositorio
```bash
git clone https://github.com/<tu_usuario>/<tu_repositorio>.git
cd <tu_repositorio>
```

### 2. Crear y activar un entorno virtual
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate
```

### 3. Actualizar pip e instalar dependencias
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configurar variables de entorno
Crea un archivo `.env` en la raíz del proyecto con al menos estas variables:

```env
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
```

**Nota**: Ajusta `config/settings.py` para leer estas variables usando python-decouple o django-environ, si aún no está configurado.

### 5. Aplicar migraciones y crear superusuario
```bash
python manage.py migrate
python manage.py createsuperuser
```

### 6. (Opcional) Recolectar archivos estáticos
```bash
python manage.py collectstatic --noinput
```

### 7. Ejecutar servidor de desarrollo
```bash
python manage.py runserver
```

Accede luego a http://127.0.0.1:8000/.

## Uso de la API

- **Registro de dispositivos**: `POST /device/register/` con `{ "mac": "001122AABBCC" }`
- **Lectura/escritura de tarjeta**: `POST /card/read/`, `POST /card/write/` (requiere NET_ENCODER_API_KEY)
- **Pinging**: `GET /device/ping/`

Consulta la carpeta `src/apps` para más detalles de los endpoints.

## Sistema de Normalización de Direcciones MAC

El proyecto incluye un sistema robusto para normalizar direcciones MAC con **contrato estricto** que previene fallos silenciosos.

### Contrato Estricto

**Aceptados como MAC válida:**
- `"AA:BB:CC:DD:EE:FF"` → `"AABBCCDDEEFF"`
- `"AABBCCDDEEFF"` → `"AABBCCDDEEFF"`
- `"aa-bb-cc-dd-ee-ff"` → `"AABBCCDDEEFF"`
- `"0xAABBCCDDEEFF"` → `"AABBCCDDEEFF"`

**Aceptados como comodín:**
- `None`, `0`, `"0"` → `"000000000000"`
- `"00:00:00:00:00:00"` → `"000000000000"`
- `"000000000000"` → `"000000000000"`

**Todo lo demás** → `ValueError: "mac inválida: 'pepino123'"`

### Casos Válidos

```python
from src.lib.utils.mac import normalize_mac_or_comodín_nullish

# MACs válidas
normalize_mac_or_comodín_nullish("55:C0:B6:D0:91:61") # "55C0B6D09161"
normalize_mac_or_comodín_nullish("55-c0-b6-d0-91-61") # "55C0B6D09161"
normalize_mac_or_comodín_nullish("0x55C0B6D09161")    # "55C0B6D09161"
normalize_mac_or_comodín_nullish("55c0b6d09161")     # "55C0B6D09161"

# comodíns (valores nulos/ceros)
normalize_mac_or_comodín_nullish(0)                   # "000000000000"
normalize_mac_or_comodín_nullish("0")                 # "000000000000"
normalize_mac_or_comodín_nullish(None)                # "000000000000"
normalize_mac_or_comodín_nullish("00:00:00:00:00:00") # "000000000000"
```

### Casos Inválidos (lanzan ValueError)

```python
# Estos lanzan ValueError, NO devuelven comodín
normalize_mac_or_comodín_nullish("")                  # ValueError: "MAC vacía"
normalize_mac_or_comodín_nullish("invalid")           # ValueError: "MAC inválida: 'invalid'"
normalize_mac_or_comodín_nullish("123456")            # ValueError: "MAC inválida: '123456'"
normalize_mac_or_comodín_nullish("pepino123")         # ValueError: "MAC inválida: 'pepino123'"
```

### Tabla de Referencia de Entradas y Resultados

| **Entrada**              | **Salida normalizada** | **Acción / Significado**                         |
|---------------------------|------------------------|--------------------------------------------------|
| `None`                   | `000000000000`         | Comodín (joker → cualquier MAC)                  |
| `0` (int)                | `000000000000`         | Comodín                                          |
| `"0"` (string)           | `000000000000`         | Comodín                                          |
| `"00:00:00:00:00:00"`    | `000000000000`         | Comodín                                          |
| `"000000000000"`         | `000000000000`         | Comodín                                          |
| `"0x000000000000"`       | `000000000000`         | Comodín                                          |
| `"55:C0:B6:D0:91:61"`    | `55C0B6D09161`         | MAC válida normalizada                           |
| `"55c0b6d09161"`         | `55C0B6D09161`         | MAC válida normalizada                           |
| `"0x55C0B6D09161"`       | `55C0B6D09161`         | MAC válida normalizada                           |
| `"55-C0-B6-D0-91-61"`    | `55C0B6D09161`         | MAC válida normalizada                           |
| `"pepino123"`            | ❌ `ValueError`        | MAC inválida → **rechazada**                     |
| `"ZZZZZZZZZZZZ"`         | ❌ `ValueError`        | MAC inválida → **rechazada**                     |
| `12345` (int no cero)    | `000000003039`         | Interpretado como valor numérico → MAC válida    |
| `"AB:CD:EF:12:34"`       | ❌ `ValueError`        | MAC inválida (longitud incorrecta)               |

### Características

- **Contrato estricto**: Rechaza explícitamente formatos inválidos
- **Sin fallos silenciosos**: ValueError en lugar de comodín universal
- **Comodín específico**: Solo para valores nulos/ceros
- **Seguro para DLL**: Siempre recibe formato válido o falla explícitamente
- **Compatibilidad**: Función `normalize_mac()` mantiene contrato anterior

### Funciones Disponibles

#### `normalize_mac_or_comodín_nullish(mac_input)` (RECOMENDADA)
Normaliza MAC con contrato estricto que previene fallos silenciosos.

**Parámetros:**
- `mac_input`: MAC en cualquier formato

**Retorna:**
- MAC normalizada en formato hexadecimal continuo (12 caracteres uppercase)
- `"000000000000"` solo para valores nulos/ceros

**Lanza:**
- `ValueError` para cualquier formato inválido

**Import:**
```python
from src.lib.utils.mac import normalize_mac_or_comodín_nullish
```

#### `normalize_mac(mac_input)` (COMPATIBILIDAD)
Función de compatibilidad que mantiene el contrato anterior.

**Parámetros:**
- `mac_input`: MAC en cualquier formato

**Retorna:**
- MAC normalizada o `"000000000000"` para cualquier entrada inválida

**Import:**
```python
from src.lib.utils.mac import normalize_mac
```

### Casos Edge

- **Strings vacíos**: Lanzan `ValueError: "MAC vacía"`
- **None/0**: Retornan `"000000000000"` (comodín)
- **Strings inválidos**: Lanzan `ValueError: "MAC inválida: 'pepino123'"`
- **Cualquier basura**: Lanza `ValueError` en lugar de comodín silencioso

### Pruebas

El sistema de normalización de MAC está completamente integrado y probado. Se puede verificar su funcionamiento ejecutando el código directamente:

```python
from src.lib.utils.mac import normalize_mac_or_comodín_nullish, normalize_mac

# Probar contrato estricto (RECOMENDADO)
print(normalize_mac_or_comodín_nullish("55:C0:B6:D0:91:61"))  # "55C0B6D09161"
print(normalize_mac_or_comodín_nullish(0))                     # "000000000000"
print(normalize_mac_or_comodín_nullish("0x55C0B6D09161"))      # "55C0B6D09161"

# Probar casos que fallan (ValueError)
try:
    normalize_mac_or_comodín_nullish("invalid")  # ValueError: "MAC inválida: 'invalid'"
except ValueError as e:
    print(f"Error esperado: {e}")

# Probar función de compatibilidad
print(normalize_mac("invalid"))                # "000000000000" (comodín silencioso)
```

## Notas finales

- Asegúrate de que los DLLs están en las rutas correctas
- Ajusta LOG_INFO, LOG_WARNING y LOG_ERROR en los módulos si quieres más o menos detalle en consola
- Para producción, desactiva DEBUG y usa un servidor WSGI (Gunicorn, uWSGI) detrás de Nginx
- El sistema de normalización de MAC está completamente integrado y listo para usar
