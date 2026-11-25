from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from flask_socketio import SocketIO
from datetime import datetime, timedelta, date, timezone
import io
import firebase_admin
from firebase_admin import credentials, firestore
import requests
from urllib.parse import quote, urlparse
import os
import json
import re
import hashlib
import hmac
import secrets
import base64
import time
from decimal import Decimal, InvalidOperation

app = Flask(__name__)

# Permitir la web publicada y los puertos locales de Flutter Web.
CORS(app, origins=[
    "https://smartwashtecsol.web.app",
    r"^http://localhost:\d+$",
    r"^http://127\.0\.0\.1:\d+$"
])

# Mantener Socket.IO con threading (sin Eventlet).
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)

# --- INICIALIZAR FIREBASE ---
firebase_env = os.environ.get("FIREBASE_CONFIG_JSON")

if firebase_env:
    cred_dict = json.loads(firebase_env)
    cred = credentials.Certificate(cred_dict)
else:
    cred = credentials.Certificate("firebase_key.json")

if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

db = firestore.client()

ADMIN_MASTER_USER = os.environ.get("ADMIN_MASTER_USER", "admin")
ADMIN_MASTER_PASS = os.environ.get("ADMIN_MASTER_PASS", "")

# Tokens de sesión de administrador para las nuevas funciones de gestión.
# Se recomienda definir ADMIN_SESSION_SECRET en Render; como transición,
# se deriva una clave del secreto de administrador ya existente.
ADMIN_SESSION_SECRET = (
        os.environ.get("ADMIN_SESSION_SECRET")
        or (ADMIN_MASTER_PASS + "|SMARTWASH_ADMIN_SESSION_V1" if ADMIN_MASTER_PASS else "")
)
ADMIN_SESSION_TTL_SECONDS = 8 * 60 * 60
# Sesiones independientes para consumidores. Se deriva del secreto de sesión
# del servidor si no se define USER_SESSION_SECRET en Render.
USER_SESSION_SECRET = (
        os.environ.get("USER_SESSION_SECRET")
        or (ADMIN_SESSION_SECRET + "|SMARTWASH_USER_SESSION_V1" if ADMIN_SESSION_SECRET else "")
)
USER_SESSION_TTL_SECONDS = 4 * 60 * 60

# Rango inicial de créditos digitales permitido en la fase de preparación.
CREDITO_MINIMO_SOLES = 1
CREDITO_MAXIMO_SOLES = 3

# Configuración privada del QR personal de Yape por propietario en Supabase Storage.
# Estas variables se configuran exclusivamente en Render. La clave secreta
# nunca debe enviarse a Flutter ni guardarse en el repositorio.
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY", "").strip()
SUPABASE_QR_BUCKET = os.environ.get(
    "SUPABASE_QR_BUCKET", "smartwash-qr-propietarios"
).strip()
YAPE_QR_MAX_BYTES = 3 * 1024 * 1024  # 3 MB por imagen
SUPABASE_STORAGE_TIMEOUT = (5, 30)


def _b64url_encode(valor):
    return base64.urlsafe_b64encode(valor).decode("utf-8").rstrip("=")


def _b64url_decode(valor):
    relleno = "=" * (-len(valor) % 4)
    return base64.urlsafe_b64decode((valor + relleno).encode("utf-8"))


def _crear_token_admin(usuario):
    """Crea un token firmado y temporal para las operaciones administrativas nuevas."""
    if not ADMIN_SESSION_SECRET:
        return None
    ahora = int(time.time())
    payload = f"{usuario}|{ahora}|{ahora + ADMIN_SESSION_TTL_SECONDS}|{secrets.token_urlsafe(12)}"
    payload_codificado = _b64url_encode(payload.encode("utf-8"))
    firma = hmac.new(
        ADMIN_SESSION_SECRET.encode("utf-8"),
        payload_codificado.encode("ascii"),
        hashlib.sha256
    ).digest()
    return f"{payload_codificado}.{_b64url_encode(firma)}"


def _admin_autorizado():
    """Valida el token firmado de administrador enviado en Authorization: Bearer."""
    encabezado = request.headers.get("Authorization", "")
    if not encabezado.startswith("Bearer ") or not ADMIN_SESSION_SECRET:
        return False
    token = encabezado[7:].strip()
    try:
        payload_codificado, firma_recibida = token.split(".", 1)
        firma_esperada = hmac.new(
            ADMIN_SESSION_SECRET.encode("utf-8"),
            payload_codificado.encode("ascii"),
            hashlib.sha256
        ).digest()
        if not hmac.compare_digest(_b64url_decode(firma_recibida), firma_esperada):
            return False
        usuario, emitido_texto, expira_texto, _nonce = _b64url_decode(
            payload_codificado
        ).decode("utf-8").split("|", 3)
        emitido = int(emitido_texto)
        expira = int(expira_texto)
        ahora = int(time.time())
        return (
                usuario == ADMIN_MASTER_USER
                and emitido <= ahora + 60
                and expira > ahora
                and expira - emitido <= ADMIN_SESSION_TTL_SECONDS
        )
    except (ValueError, TypeError, UnicodeDecodeError, base64.binascii.Error):
        return False


def _crear_token_consumidor(usuario):
    """Crea una sesión firmada y temporal para un consumidor autenticado."""
    if not USER_SESSION_SECRET:
        return None
    ahora = int(time.time())
    expira = ahora + USER_SESSION_TTL_SECONDS
    payload = f"consumidor|{usuario}|{ahora}|{expira}|{secrets.token_urlsafe(12)}"
    payload_codificado = _b64url_encode(payload.encode("utf-8"))
    firma = hmac.new(
        USER_SESSION_SECRET.encode("utf-8"),
        payload_codificado.encode("ascii"),
        hashlib.sha256
    ).digest()
    return f"{payload_codificado}.{_b64url_encode(firma)}"


def _consumidor_autorizado():
    """Valida el token de consumidor y devuelve su usuario; None si no es válido."""
    encabezado = request.headers.get("Authorization", "")
    if not encabezado.startswith("Bearer ") or not USER_SESSION_SECRET:
        return None
    token = encabezado[7:].strip()
    try:
        payload_codificado, firma_recibida = token.split(".", 1)
        firma_esperada = hmac.new(
            USER_SESSION_SECRET.encode("utf-8"),
            payload_codificado.encode("ascii"),
            hashlib.sha256
        ).digest()
        if not hmac.compare_digest(_b64url_decode(firma_recibida), firma_esperada):
            return None
        rol, usuario, emitido_texto, expira_texto, _nonce = _b64url_decode(
            payload_codificado
        ).decode("utf-8").split("|", 4)
        emitido = int(emitido_texto)
        expira = int(expira_texto)
        ahora = int(time.time())
        if (rol != "consumidor" or not usuario or emitido > ahora + 60
                or expira <= ahora or expira - emitido > USER_SESSION_TTL_SECONDS):
            return None
        consumidor_doc = db.collection("consumidores").document(usuario).get()
        if not consumidor_doc.exists:
            return None
        consumidor = consumidor_doc.to_dict() or {}
        if consumidor.get("activo", True) is not True:
            return None
        return usuario
    except (ValueError, TypeError, UnicodeDecodeError, base64.binascii.Error):
        return None


# Un ESP32 se considera conectado si envio heartbeat en los ultimos 150 segundos.
ESP32_ONLINE_TIMEOUT_SECONDS = 150

# --- FUNCIONES DE APOYO ---
def obtener_clientes_db():
    docs = db.collection("clientes").stream()
    return {doc.id: doc.to_dict() for doc in docs}


def obtener_clientes_para_admin():
    """Devuelve datos de clientes sin incluir sus contraseñas (ni hashes)."""
    clientes = obtener_clientes_db()
    resultado = {}
    for usuario, datos in clientes.items():
        datos_seguros = dict(datos or {})
        datos_seguros.pop("password", None)
        resultado[usuario] = datos_seguros
    return resultado


PASSWORD_HASH_ITERATIONS = 260000


def _crear_hash_password(password):
    """Genera un hash PBKDF2 con sal aleatoria usando solo la biblioteca estándar."""
    sal = secrets.token_hex(16)
    derivada = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), sal.encode("utf-8"), PASSWORD_HASH_ITERATIONS
    )
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${sal}${derivada.hex()}"


def _verificar_password(password_guardada, password_ingresada):
    """Acepta hashes PBKDF2 nuevos y contraseñas antiguas en texto plano."""
    if not isinstance(password_guardada, str) or not password_guardada:
        return False
    if password_guardada.startswith("pbkdf2_sha256$"):
        try:
            algoritmo, iteraciones_texto, sal, hash_esperado = password_guardada.split("$", 3)
            iteraciones = int(iteraciones_texto)
            if algoritmo != "pbkdf2_sha256" or not 100000 <= iteraciones <= 1000000:
                return False
            derivada = hashlib.pbkdf2_hmac(
                "sha256", password_ingresada.encode("utf-8"), sal.encode("utf-8"), iteraciones
            ).hex()
            return hmac.compare_digest(derivada, hash_esperado)
        except (ValueError, TypeError):
            return False
    # Compatibilidad con cuentas antiguas que guardaban la contraseña en texto plano.
    return hmac.compare_digest(password_guardada.encode("utf-8"), password_ingresada.encode("utf-8"))


def _migrar_password_si_antigua(ref, password_guardada):
    if isinstance(password_guardada, str) and not password_guardada.startswith("pbkdf2_sha256$"):
        ref.update({"password": _crear_hash_password(password_guardada)})


def _timestamp_a_datetime(valor):
    """Normaliza Timestamp de Firestore o texto ISO a datetime UTC."""
    if isinstance(valor, datetime):
        dt = valor
    elif isinstance(valor, str):
        try:
            dt = datetime.fromisoformat(valor.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _esp32_esta_conectado(datos):
    ultima = _timestamp_a_datetime(datos.get("ultima_conexion"))
    if ultima is None:
        return False

    segundos = (datetime.now(timezone.utc) - ultima).total_seconds()
    # Margen pequeño por diferencias de reloj; el timestamp normalmente
    # procede de firestore.SERVER_TIMESTAMP.
    return -60 <= segundos <= ESP32_ONLINE_TIMEOUT_SECONDS


def obtener_cajas_db():
    """Devuelve cajas con ID y estado de conectividad calculado por heartbeat."""
    resultado = {}
    for doc in db.collection("cajas").stream():
        datos = doc.to_dict() or {}
        datos.setdefault("id", doc.id)
        conectado = _esp32_esta_conectado(datos)
        datos["conectado"] = conectado
        datos["estado_conexion"] = "conectado" if conectado else "sin_conexion"
        resultado[doc.id] = datos
    return resultado


def convertir_valores_para_json(valor):
    """Convierte tipos de Firestore (por ejemplo timestamps) a JSON seguro."""
    if isinstance(valor, datetime):
        return valor.isoformat()
    if isinstance(valor, date):
        return valor.isoformat()
    if isinstance(valor, dict):
        return {str(clave): convertir_valores_para_json(dato)
                for clave, dato in valor.items()}
    if isinstance(valor, (list, tuple)):
        return [convertir_valores_para_json(dato) for dato in valor]
    return valor


def emitir_actualizacion_cajas():
    """Emite cambios en tiempo real sin hacer fallar el POST ya guardado."""
    try:
        cajas = obtener_cajas_db()
        cajas_json = convertir_valores_para_json(cajas)
        socketio.emit("actualizacion_cajas", cajas_json)
    except Exception:
        # Una falla de Socket.IO no debe convertir en HTTP 500 una escritura
        # que ya se realizó correctamente en Firestore.
        app.logger.exception(
            "No se pudo emitir actualizacion_cajas por Socket.IO. "
            "La operación de Firestore puede haberse guardado correctamente."
        )


def _verificar_propietario_para_qr(usuario, password_actual):
    """Comprueba cuenta, rol, aprobación TECSOL y contraseña para operaciones QR."""
    usuario = str(usuario or "").strip()
    password_actual = str(password_actual or "")
    if not usuario or not password_actual:
        return None, None, ("Se requiere el usuario y la contraseña actual del propietario.", 400)

    propietario_ref = db.collection("clientes").document(usuario)
    propietario_doc = propietario_ref.get()
    if not propietario_doc.exists:
        return None, None, ("No se encontró la cuenta del propietario.", 404)

    propietario = propietario_doc.to_dict() or {}
    rol = str(propietario.get("rol") or "propietario").strip().lower()
    if rol not in ("propietario", "cliente"):
        return None, None, ("Esta cuenta no corresponde a un propietario.", 403)
    if propietario.get("aprobado", False) is not True:
        return None, None, ("La cuenta todavía no está habilitada por TECSOL.", 403)

    password_guardada = propietario.get("password", "")
    if not _verificar_password(password_guardada, password_actual):
        return None, None, ("La contraseña actual es incorrecta.", 401)

    _migrar_password_si_antigua(propietario_ref, password_guardada)
    if rol != "propietario":
        propietario_ref.update({"rol": "propietario"})
    return propietario_ref, propietario, None


def _supabase_storage_configuracion():
    """Valida que Render tenga las credenciales del almacenamiento Supabase."""
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY or not SUPABASE_QR_BUCKET:
        raise RuntimeError(
            "Faltan SUPABASE_URL, SUPABASE_SECRET_KEY o SUPABASE_QR_BUCKET en Render."
        )
    parsed = urlparse(SUPABASE_URL)
    if parsed.scheme != "https" or not parsed.netloc:
        raise RuntimeError("SUPABASE_URL debe ser una URL HTTPS válida del proyecto.")
    if not re.fullmatch(r"[A-Za-z0-9_-]{3,100}", SUPABASE_QR_BUCKET):
        raise RuntimeError("SUPABASE_QR_BUCKET tiene un nombre no válido.")


def _supabase_headers(content_type=None):
    """Crea cabeceras servidor-a-servidor con la clave secreta de Supabase."""
    _supabase_storage_configuracion()
    # Las claves sb_secret_ son claves API opacas, no JWT.
    # Deben enviarse en apikey; no como Authorization: Bearer.
    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Accept": "application/json",
    }
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def _supabase_storage_url(recurso):
    return f"{SUPABASE_URL}/storage/v1/{recurso.lstrip('/')}"


def _supabase_subir_qr(storage_path, contenido, content_type):
    """Sube una imagen nueva al bucket privado sin sobrescribir archivos."""
    ruta = quote(storage_path, safe="/")
    headers = _supabase_headers(content_type)
    headers["x-upsert"] = "false"
    headers["cache-control"] = "0"
    try:
        response = requests.post(
            _supabase_storage_url(f"object/{SUPABASE_QR_BUCKET}/{ruta}"),
            headers=headers,
            data=contenido,
            timeout=SUPABASE_STORAGE_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise RuntimeError("No fue posible conectar con Supabase Storage.") from exc
    if not response.ok:
        detalle = (response.text or "")[:350]
        raise RuntimeError(
            f"Supabase Storage rechazó la carga (HTTP {response.status_code}): {detalle}"
        )
    return response


def _supabase_descargar_qr(storage_path):
    """Descarga un objeto privado; el archivo nunca se sirve desde una URL pública."""
    ruta = quote(storage_path, safe="/")
    try:
        response = requests.get(
            _supabase_storage_url(
                f"object/authenticated/{SUPABASE_QR_BUCKET}/{ruta}"
            ),
            headers=_supabase_headers(),
            timeout=SUPABASE_STORAGE_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise RuntimeError("No fue posible conectar con Supabase Storage.") from exc
    if not response.ok:
        detalle = (response.text or "")[:350]
        raise RuntimeError(
            f"Supabase Storage no pudo recuperar el QR (HTTP {response.status_code}): {detalle}"
        )
    return response.content


def _supabase_eliminar_qr(storage_path):
    """Elimina un único objeto antiguo del bucket privado."""
    try:
        response = requests.delete(
            _supabase_storage_url(f"object/{SUPABASE_QR_BUCKET}"),
            headers=_supabase_headers("application/json"),
            json={"prefixes": [storage_path]},
            timeout=SUPABASE_STORAGE_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise RuntimeError("No fue posible conectar con Supabase Storage.") from exc
    if not response.ok:
        detalle = (response.text or "")[:350]
        raise RuntimeError(
            f"Supabase Storage no pudo eliminar el archivo anterior (HTTP {response.status_code}): {detalle}"
        )
    return True


def _detectar_tipo_imagen_qr(contenido):
    """Acepta únicamente firmas binarias PNG, JPEG o WEBP; no confía en la extensión."""
    if contenido.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", "png"
    if contenido.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", "jpg"
    if len(contenido) >= 12 and contenido[:4] == b"RIFF" and contenido[8:12] == b"WEBP":
        return "image/webp", "webp"
    return None, None


# --- RUTAS DE LA API ---

@app.route("/api/registro", methods=["POST"])
def registrar_cliente():
    datos = request.get_json(silent=True) or {}
    usuario = str(datos.get("usuario") or "").strip()
    password = str(datos.get("password") or "")

    if not usuario or not password:
        return jsonify({"status": "error", "mensaje": "Faltan datos"}), 400

    clientes = obtener_clientes_db()
    consumidor_existente = db.collection("consumidores").document(usuario).get().exists
    if usuario in clientes or consumidor_existente or usuario == ADMIN_MASTER_USER:
        return jsonify({"status": "error", "mensaje": "El usuario ya existe"}), 400

    db.collection("clientes").document(usuario).set({
        "password": _crear_hash_password(password),
        "rol": "propietario",
        # Nombre inicial del local; el propietario puede cambiarlo desde
        # su panel mediante la ruta que verifica su contraseña actual.
        "nombre_local": usuario,
        "aprobado": False
    })
    return jsonify({
        "status": "ok",
        "mensaje": "Registro exitoso. Espere activación del administrador."
    }), 201


@app.route("/api/login", methods=["POST"])
def login():
    datos = request.get_json(silent=True) or {}
    usuario = str(datos.get("usuario") or "").strip()
    password = str(datos.get("password") or "")

    if not usuario or not password:
        return jsonify({"status": "error", "mensaje": "Faltan usuario y contraseña"}), 400

    # Perfil 1: administrador TECSOL.
    if usuario == ADMIN_MASTER_USER:
        if not ADMIN_MASTER_PASS:
            app.logger.error("Falta configurar ADMIN_MASTER_PASS")
            return jsonify({
                "status": "error",
                "mensaje": "El acceso de administrador no está configurado en el servidor."
            }), 503

        if password != ADMIN_MASTER_PASS:
            return jsonify({"status": "error", "mensaje": "Credenciales incorrectas"}), 401

        token_admin = _crear_token_admin(usuario)
        if not token_admin:
            app.logger.error("No se pudo generar el token de administrador")
            return jsonify({
                "status": "error",
                "mensaje": "La sesión administrativa no está configurada en el servidor."
            }), 503

        return jsonify({
            "status": "ok",
            "rol": "admin",
            "token_admin": token_admin,
            "clientes": obtener_clientes_para_admin()
        }), 200

    # Perfil 2: propietario de autolavado. Conserva la aprobación TECSOL.
    cliente_ref = db.collection("clientes").document(usuario)
    cliente_doc = cliente_ref.get()
    if cliente_doc.exists:
        cliente = cliente_doc.to_dict() or {}
        password_guardada = cliente.get("password", "")
        if not _verificar_password(password_guardada, password):
            return jsonify({"status": "error", "mensaje": "Credenciales incorrectas"}), 401

        _migrar_password_si_antigua(cliente_ref, password_guardada)
        if not cliente.get("aprobado", False):
            return jsonify({
                "status": "error",
                "mensaje": "Cuenta pendiente de activación por TECSOL."
            }), 403

        config_qr_doc = db.collection("configuracion_yape").document(usuario).get()
        if config_qr_doc.exists:
            config_qr = config_qr_doc.to_dict() or {}
        else:
            config_qr = {}
        qr_registrado = bool(config_qr.get("storage_path"))
        qr_activo = qr_registrado and config_qr.get("activo", False) is True
        qr_estado = "activo" if qr_activo else (
            "desactivado" if qr_registrado else "no_configurado"
        )

        return jsonify({
            "status": "ok",
            "rol": "propietario",
            "usuario": usuario,
            "nombre_local": cliente.get("nombre_local") or usuario,
            # Compatibilidad: el campo antiguo representa QR activo.
            "yape_qr_configurado": qr_activo,
            # Campos explícitos para diferenciar los tres estados en Flutter.
            "yape_qr_registrado": qr_registrado,
            "yape_qr_activo": qr_activo,
            "yape_qr_estado": qr_estado
        }), 200

    # Perfil 3: consumidor. No requiere aprobación del administrador.
    consumidor_ref = db.collection("consumidores").document(usuario)
    consumidor_doc = consumidor_ref.get()
    if consumidor_doc.exists:
        consumidor = consumidor_doc.to_dict() or {}
        password_guardada = consumidor.get("password", "")
        if not _verificar_password(password_guardada, password):
            return jsonify({"status": "error", "mensaje": "Credenciales incorrectas"}), 401
        if consumidor.get("activo", True) is not True:
            return jsonify({"status": "error", "mensaje": "La cuenta se encuentra desactivada."}), 403

        _migrar_password_si_antigua(consumidor_ref, password_guardada)
        token_consumidor = _crear_token_consumidor(usuario)
        if not token_consumidor:
            app.logger.error("No se pudo generar el token de sesión del consumidor.")
            return jsonify({
                "status": "error",
                "mensaje": "La sesión del consumidor no está configurada en el servidor."
            }), 503
        return jsonify({
            "status": "ok",
            "rol": "consumidor",
            "usuario": usuario,
            "nombre": consumidor.get("nombre") or usuario,
            "token_consumidor": token_consumidor
        }), 200

    return jsonify({"status": "error", "mensaje": "Credenciales incorrectas"}), 401


@app.route("/api/registro_consumidor", methods=["POST"])
def registrar_consumidor():
    datos = request.get_json(silent=True) or {}
    usuario = str(datos.get("usuario") or "").strip()
    password = str(datos.get("password") or "")
    nombre = str(datos.get("nombre") or "").strip()
    telefono = str(datos.get("telefono") or "").strip()

    if not usuario or not password or not nombre:
        return jsonify({"status": "error", "mensaje": "Completa nombre, usuario y contraseña."}), 400
    if len(password) < 6:
        return jsonify({"status": "error", "mensaje": "La contraseña debe tener al menos 6 caracteres."}), 400
    if usuario == ADMIN_MASTER_USER:
        return jsonify({"status": "error", "mensaje": "El usuario ya está reservado."}), 400

    if db.collection("clientes").document(usuario).get().exists:
        return jsonify({"status": "error", "mensaje": "Ese usuario ya pertenece a un local."}), 409
    consumidor_ref = db.collection("consumidores").document(usuario)
    if consumidor_ref.get().exists:
        return jsonify({"status": "error", "mensaje": "El usuario ya existe."}), 409

    consumidor_ref.set({
        "nombre": nombre,
        "telefono": telefono,
        "password": _crear_hash_password(password),
        "rol": "consumidor",
        "activo": True,
        "fecha_registro": firestore.SERVER_TIMESTAMP
    })
    return jsonify({
        "status": "ok",
        "mensaje": "Cuenta de consumidor creada correctamente. Ya puedes iniciar sesión."
    }), 201


@app.route("/api/admin/aprobar_cliente", methods=["POST"])
def aprobar_cliente():
    datos = request.get_json(silent=True) or {}
    usuario = str(datos.get("usuario") or "").strip()
    estado = bool(datos.get("aprobado", True))

    cliente_ref = db.collection("clientes").document(usuario)
    if cliente_ref.get().exists:
        cliente_ref.update({"aprobado": estado})
        return jsonify({"status": "ok"})
    return jsonify({"status": "error"}), 404


@app.route("/api/admin/cambiar_password", methods=["POST"])
def admin_cambiar_password():
    datos = request.get_json(silent=True) or {}
    usuario = str(datos.get("usuario") or "").strip()
    nuevo_password = str(datos.get("nuevo_password") or "")

    cliente_ref = db.collection("clientes").document(usuario)
    if cliente_ref.get().exists and nuevo_password:
        if len(nuevo_password) < 6:
            return jsonify({"status": "error", "mensaje": "La contraseña debe tener al menos 6 caracteres."}), 400
        cliente_ref.update({"password": _crear_hash_password(nuevo_password)})
        return jsonify({"status": "ok"})
    return jsonify({"status": "error"}), 404


# --- GESTIÓN DE ESTACIONES FÍSICAS (SOLO ADMIN TECSOL) ---
@app.route("/api/admin/estaciones", methods=["GET"])
def admin_listar_estaciones():
    if not _admin_autorizado():
        return jsonify({"status": "error", "mensaje": "Sesión administrativa inválida o vencida."}), 401

    clientes = obtener_clientes_db()
    estaciones = []
    for doc in db.collection("estaciones").stream():
        datos = doc.to_dict() or {}
        propietario = str(datos.get("propietario") or "")
        perfil = clientes.get(propietario, {}) or {}
        estaciones.append({
            "id": doc.id,
            "nombre": str(datos.get("nombre") or "Estación sin nombre"),
            "propietario": propietario,
            "nombre_local": str(perfil.get("nombre_local") or propietario),
            "activo": datos.get("activo", True) is True,
            "fecha_creacion": datos.get("fecha_creacion")
        })

    estaciones.sort(key=lambda item: (
        item["nombre_local"].lower(), item["nombre"].lower()
    ))
    return jsonify({"status": "ok", "estaciones": convertir_valores_para_json(estaciones)}), 200


@app.route("/api/admin/estaciones", methods=["POST"])
def admin_crear_estacion():
    if not _admin_autorizado():
        return jsonify({"status": "error", "mensaje": "Sesión administrativa inválida o vencida."}), 401

    datos = request.get_json(silent=True) or {}
    nombre = re.sub(r"\s+", " ", str(datos.get("nombre") or "").strip())
    propietario = str(datos.get("propietario") or "").strip()

    if len(nombre) < 2 or len(nombre) > 50:
        return jsonify({"status": "error", "mensaje": "El nombre de la estación debe tener entre 2 y 50 caracteres."}), 400
    if not propietario:
        return jsonify({"status": "error", "mensaje": "Selecciona el propietario de esta estación."}), 400

    propietario_ref = db.collection("clientes").document(propietario)
    propietario_doc = propietario_ref.get()
    if not propietario_doc.exists:
        return jsonify({"status": "error", "mensaje": "No se encontró el propietario seleccionado."}), 404

    perfil = propietario_doc.to_dict() or {}
    if perfil.get("aprobado", False) is not True:
        return jsonify({"status": "error", "mensaje": "El propietario debe estar aprobado por TECSOL antes de crear estaciones."}), 403

    nombre_normalizado = nombre.casefold()
    for doc in db.collection("estaciones").where("propietario", "==", propietario).stream():
        existente = doc.to_dict() or {}
        if str(existente.get("nombre") or "").strip().casefold() == nombre_normalizado:
            return jsonify({"status": "error", "mensaje": "Ese propietario ya tiene una estación con ese nombre."}), 409

    estacion_ref = db.collection("estaciones").document()
    estacion_ref.set({
        "nombre": nombre,
        "propietario": propietario,
        "activo": True,
        "fecha_creacion": firestore.SERVER_TIMESTAMP,
        "fecha_actualizacion": firestore.SERVER_TIMESTAMP
    })

    return jsonify({
        "status": "ok",
        "mensaje": "Estación creada correctamente.",
        "estacion": {
            "id": estacion_ref.id,
            "nombre": nombre,
            "propietario": propietario,
            "nombre_local": str(perfil.get("nombre_local") or propietario),
            "activo": True
        }
    }), 201


@app.route("/api/admin/estaciones/<id_estacion>", methods=["PUT"])
def admin_actualizar_estacion(id_estacion):
    if not _admin_autorizado():
        return jsonify({"status": "error", "mensaje": "Sesión administrativa inválida o vencida."}), 401

    datos = request.get_json(silent=True) or {}
    estacion_ref = db.collection("estaciones").document(id_estacion)
    estacion_doc = estacion_ref.get()
    if not estacion_doc.exists:
        return jsonify({"status": "error", "mensaje": "No se encontró la estación."}), 404

    actual = estacion_doc.to_dict() or {}
    propietario = str(actual.get("propietario") or "")
    cambios = {}

    if "nombre" in datos:
        nombre = re.sub(r"\s+", " ", str(datos.get("nombre") or "").strip())
        if len(nombre) < 2 or len(nombre) > 50:
            return jsonify({"status": "error", "mensaje": "El nombre debe tener entre 2 y 50 caracteres."}), 400
        for doc in db.collection("estaciones").where("propietario", "==", propietario).stream():
            if doc.id == id_estacion:
                continue
            existente = doc.to_dict() or {}
            if str(existente.get("nombre") or "").strip().casefold() == nombre.casefold():
                return jsonify({"status": "error", "mensaje": "Ese propietario ya tiene otra estación con ese nombre."}), 409
        cambios["nombre"] = nombre

    if "activo" in datos:
        if not isinstance(datos.get("activo"), bool):
            return jsonify({"status": "error", "mensaje": "El estado de la estación no es válido."}), 400
        cambios["activo"] = datos["activo"]

    if not cambios:
        return jsonify({"status": "error", "mensaje": "No se recibieron cambios para guardar."}), 400

    cambios["fecha_actualizacion"] = firestore.SERVER_TIMESTAMP
    estacion_ref.update(cambios)
    return jsonify({"status": "ok", "mensaje": "Estación actualizada correctamente."}), 200


@app.route("/api/admin/cajas/<id_caja>/configuracion", methods=["PUT"])
def admin_configurar_caja(id_caja):
    """Actualiza los datos administrativos de una máquina y su estación en una sola operación."""
    if not _admin_autorizado():
        return jsonify({"status": "error", "mensaje": "Sesión administrativa inválida o vencida. Vuelve a ingresar."}), 401

    datos = request.get_json(silent=True) or {}
    nombre = re.sub(r"\s+", " ", str(datos.get("nombre") or "").strip())
    tipo = str(datos.get("tipo") or "").strip()
    propietario = str(datos.get("propietario") or "sin_asignar").strip()
    estacion_id = str(datos.get("estacion_id") or "").strip()
    activo = datos.get("activo", True)

    if len(nombre) < 1 or len(nombre) > 60:
        return jsonify({"status": "error", "mensaje": "El nombre de la máquina debe tener entre 1 y 60 caracteres."}), 400
    tipos_validos = {"Agua", "Shampoo", "Silicona", "Aspiradora", "No asignado"}
    if tipo not in tipos_validos:
        return jsonify({"status": "error", "mensaje": "El tipo de servicio seleccionado no es válido."}), 400
    if not isinstance(activo, bool):
        return jsonify({"status": "error", "mensaje": "El estado de la licencia no es válido."}), 400

    caja_ref = db.collection("cajas").document(id_caja)
    caja_doc = caja_ref.get()
    if not caja_doc.exists:
        return jsonify({"status": "error", "mensaje": "No se encontró la máquina seleccionada."}), 404
    caja_actual = caja_doc.to_dict() or {}

    if propietario != "sin_asignar":
        propietario_doc = db.collection("clientes").document(propietario).get()
        if not propietario_doc.exists:
            return jsonify({"status": "error", "mensaje": "No se encontró el propietario seleccionado."}), 404

    estacion_datos = None
    if estacion_id:
        if propietario == "sin_asignar":
            return jsonify({"status": "error", "mensaje": "Primero asigna la máquina a un propietario para vincularla con una estación."}), 400

        estacion_ref = db.collection("estaciones").document(estacion_id)
        estacion_doc = estacion_ref.get()
        if not estacion_doc.exists:
            return jsonify({"status": "error", "mensaje": "La estación seleccionada ya no existe. Actualiza la lista e inténtalo nuevamente."}), 404

        estacion_datos = estacion_doc.to_dict() or {}
        if str(estacion_datos.get("propietario") or "") != propietario:
            return jsonify({"status": "error", "mensaje": "La estación seleccionada no pertenece al propietario de esta máquina."}), 403
        if (estacion_datos.get("activo", True) is not True
                and str(caja_actual.get("estacion_id") or "") != estacion_id):
            return jsonify({"status": "error", "mensaje": "La estación está deshabilitada. Actívala antes de asignar una máquina nueva."}), 409

    # Solo se actualizan los campos de configuración. Se conservan ingresos,
    # historial, heartbeat, MAC y segundos_por_sol.
    cambios = {
        "nombre": nombre,
        "tipo": tipo,
        "activo": activo,
        "propietario": propietario,
        "estado_registro": "asignada" if propietario != "sin_asignar" else "pendiente",
        "fecha_actualizacion_configuracion": firestore.SERVER_TIMESTAMP,
    }
    if estacion_id:
        cambios["estacion_id"] = estacion_id
        cambios["estacion_nombre"] = str(estacion_datos.get("nombre") or "Estación")
    else:
        cambios["estacion_id"] = firestore.DELETE_FIELD
        cambios["estacion_nombre"] = firestore.DELETE_FIELD

    caja_ref.update(cambios)
    emitir_actualizacion_cajas()

    return jsonify({
        "status": "ok",
        "mensaje": "Máquina actualizada y estación vinculada correctamente." if estacion_id else "Máquina actualizada. Quedó sin estación asignada.",
        "id_caja": id_caja,
        "propietario": propietario,
        "estacion_id": estacion_id or None,
        "estacion_nombre": str(estacion_datos.get("nombre")) if estacion_datos else None,
    }), 200


@app.route("/api/propietario/actualizar_nombre_local", methods=["POST"])
def propietario_actualizar_nombre_local():
    """Actualiza el nombre comercial tras verificar las credenciales del propietario."""
    datos = request.get_json(silent=True) or {}
    usuario = str(datos.get("usuario") or "").strip()
    password_actual = str(datos.get("password_actual") or "")
    nombre_local = str(datos.get("nombre_local") or "").strip()

    if not usuario or not password_actual or not nombre_local:
        return jsonify({
            "status": "error",
            "mensaje": "Completa el nombre comercial y tu contraseña actual."
        }), 400

    if len(nombre_local) < 2 or len(nombre_local) > 60:
        return jsonify({
            "status": "error",
            "mensaje": "El nombre comercial debe tener entre 2 y 60 caracteres."
        }), 400

    cliente_ref = db.collection("clientes").document(usuario)
    cliente_doc = cliente_ref.get()
    if not cliente_doc.exists:
        return jsonify({"status": "error", "mensaje": "No se encontró la cuenta del propietario."}), 404

    cliente = cliente_doc.to_dict() or {}
    # Los registros antiguos de la colección "clientes" pueden no tener rol
    # o conservar el rol histórico "cliente"; ambos representan propietarios.
    rol_cliente = str(cliente.get("rol") or "propietario").strip().lower()
    if rol_cliente not in ("propietario", "cliente"):
        return jsonify({"status": "error", "mensaje": "Esta cuenta no corresponde a un propietario."}), 403
    if cliente.get("aprobado", False) is not True:
        return jsonify({"status": "error", "mensaje": "La cuenta todavía no está habilitada por TECSOL."}), 403

    password_guardada = cliente.get("password", "")
    if not _verificar_password(password_guardada, password_actual):
        return jsonify({"status": "error", "mensaje": "La contraseña actual es incorrecta."}), 401

    _migrar_password_si_antigua(cliente_ref, password_guardada)
    cliente_ref.update({
        "nombre_local": nombre_local,
        "nombre_local_actualizado": firestore.SERVER_TIMESTAMP
    })

    return jsonify({
        "status": "ok",
        "mensaje": "El nombre comercial se actualizó correctamente.",
        "nombre_local": nombre_local
    }), 200


@app.route("/api/propietario/yape/qr", methods=["POST"])
def propietario_subir_qr_yape():
    """Guarda/reemplaza el QR del propietario en Storage privado; no habilita cobros."""
    usuario = str(request.form.get("usuario") or "").strip()
    password_actual = str(request.form.get("password_actual") or "")
    archivo = request.files.get("archivo")

    _ref, _perfil, error = _verificar_propietario_para_qr(usuario, password_actual)
    if error:
        mensaje, codigo = error
        return jsonify({"status": "error", "mensaje": mensaje}), codigo

    if archivo is None or not archivo.filename:
        return jsonify({"status": "error", "mensaje": "Selecciona una imagen de tu QR de Yape."}), 400

    contenido = archivo.stream.read(YAPE_QR_MAX_BYTES + 1)
    if not contenido:
        return jsonify({"status": "error", "mensaje": "La imagen seleccionada está vacía."}), 400
    if len(contenido) > YAPE_QR_MAX_BYTES:
        return jsonify({"status": "error", "mensaje": "La imagen supera el límite permitido de 3 MB."}), 413

    content_type, extension = _detectar_tipo_imagen_qr(contenido)
    if not content_type:
        return jsonify({
            "status": "error",
            "mensaje": "Formato no admitido. Utiliza una imagen PNG, JPG o WEBP."
        }), 415

    storage_path = ""
    try:
        nombre_archivo = os.path.basename(str(archivo.filename or "qr_yape"))[:100]
        # Cada nueva imagen recibe una ruta distinta. Así evitamos sobrescrituras
        # y conservamos el QR anterior hasta que Firestore confirme el reemplazo.
        usuario_ruta = quote(usuario, safe="")
        storage_path = f"yape_qr/{usuario_ruta}/{secrets.token_hex(16)}.{extension}"
        _supabase_subir_qr(storage_path, contenido, content_type)

        config_ref = db.collection("configuracion_yape").document(usuario)
        config_anterior_doc = config_ref.get()
        config_anterior = config_anterior_doc.to_dict() or {} if config_anterior_doc.exists else {}
        path_anterior = str(config_anterior.get("storage_path") or "")

        try:
            config_ref.set({
                "propietario": usuario,
                "activo": True,
                "storage_provider": "supabase",
                "storage_bucket": SUPABASE_QR_BUCKET,
                "storage_path": storage_path,
                "nombre_archivo": nombre_archivo,
                "content_type": content_type,
                "tamano_bytes": len(contenido),
                "validacion": "pendiente",
                "habilitado_para_cobros": False,
                "actualizado_en": firestore.SERVER_TIMESTAMP
            }, merge=True)
        except Exception:
            try:
                _supabase_eliminar_qr(storage_path)
            except Exception:
                app.logger.exception("No se pudo limpiar un QR nuevo tras fallo al guardar Firestore.")
            raise

        # El archivo anterior solo se elimina después de guardar la nueva ruta.
        if path_anterior and path_anterior != storage_path:
            try:
                _supabase_eliminar_qr(path_anterior)
            except Exception:
                app.logger.exception("No se pudo eliminar el QR anterior del propietario %s.", usuario)

        return jsonify({
            "status": "ok",
            "mensaje": "El QR se guardó correctamente en almacenamiento privado. Los cobros siguen deshabilitados hasta completar la validación de Yape.",
            "qr_configurado": True,
            "activo": True,
            "validacion": "pendiente",
            "habilitado_para_cobros": False
        }), 201
    except RuntimeError as e:
        app.logger.error("Configuración de Supabase Storage incompleta o no disponible: %s", str(e))
        return jsonify({
            "status": "error",
            "mensaje": "Supabase Storage no está configurado o no pudo completar la operación. Verifica las variables de Render y el bucket privado."
        }), 503
    except Exception:
        app.logger.exception("Error al almacenar el QR de Yape del propietario %s.", usuario)
        return jsonify({
            "status": "error",
            "mensaje": "No se pudo almacenar la imagen en Supabase Storage. Revisa los registros del servidor."
        }), 503


@app.route("/api/propietario/yape/qr/preview", methods=["POST"])
def propietario_previsualizar_qr_yape():
    """Entrega el QR al propio propietario tras revalidar su contraseña; no usa URL pública."""
    datos = request.get_json(silent=True) or {}
    usuario = str(datos.get("usuario") or "").strip()
    password_actual = str(datos.get("password_actual") or "")
    _ref, _perfil, error = _verificar_propietario_para_qr(usuario, password_actual)
    if error:
        mensaje, codigo = error
        return jsonify({"status": "error", "mensaje": mensaje}), codigo

    config_doc = db.collection("configuracion_yape").document(usuario).get()
    if not config_doc.exists:
        return jsonify({"status": "error", "mensaje": "Todavía no has registrado un QR de Yape."}), 404
    config = config_doc.to_dict() or {}
    # El propietario puede consultar su imagen incluso si el QR está desactivado.
    # La contraseña se vuelve a comprobar arriba y la respuesta no se almacena en caché.
    if not config.get("storage_path"):
        return jsonify({"status": "error", "mensaje": "No hay una imagen QR guardada para esta cuenta."}), 404

    try:
        contenido = _supabase_descargar_qr(str(config["storage_path"]))
        content_type = str(config.get("content_type") or "image/png")
        response = send_file(
            io.BytesIO(contenido),
            mimetype=content_type,
            as_attachment=False,
            download_name="qr-yape-propietario"
        )
        response.headers["Cache-Control"] = "private, no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response
    except RuntimeError as e:
        app.logger.error("Error de configuración o descarga de Supabase Storage: %s", str(e))
        return jsonify({"status": "error", "mensaje": "Supabase Storage no está configurado o no pudo recuperar el QR."}), 503
    except Exception:
        app.logger.exception("Error al recuperar el QR privado del propietario %s.", usuario)
        return jsonify({"status": "error", "mensaje": "No se pudo cargar el QR guardado."}), 503


@app.route("/api/propietario/yape/qr/desactivar", methods=["POST"])
def propietario_desactivar_qr_yape():
    """Deshabilita el QR sin borrar la imagen ni los registros del propietario."""
    datos = request.get_json(silent=True) or {}
    usuario = str(datos.get("usuario") or "").strip()
    password_actual = str(datos.get("password_actual") or "")
    _ref, _perfil, error = _verificar_propietario_para_qr(usuario, password_actual)
    if error:
        mensaje, codigo = error
        return jsonify({"status": "error", "mensaje": mensaje}), codigo

    config_ref = db.collection("configuracion_yape").document(usuario)
    config_doc = config_ref.get()
    if not config_doc.exists:
        return jsonify({"status": "error", "mensaje": "No hay un QR registrado para desactivar."}), 404

    config_ref.update({
        "activo": False,
        "habilitado_para_cobros": False,
        "desactivado_en": firestore.SERVER_TIMESTAMP,
        "actualizado_en": firestore.SERVER_TIMESTAMP
    })
    return jsonify({
        "status": "ok",
        "mensaje": "El QR quedó deshabilitado. La imagen se conserva para poder reemplazarla posteriormente.",
        "qr_configurado": False,
        "qr_registrado": True,
        "qr_activo": False,
        "qr_estado": "desactivado",
        "habilitado_para_cobros": False
    }), 200


@app.route("/api/propietario/yape/qr/activar", methods=["POST"])
def propietario_reactivar_qr_yape():
    """Reactiva el QR previamente guardado, sin habilitar pagos ni cambiar su archivo."""
    datos = request.get_json(silent=True) or {}
    usuario = str(datos.get("usuario") or "").strip()
    password_actual = str(datos.get("password_actual") or "")
    _ref, _perfil, error = _verificar_propietario_para_qr(usuario, password_actual)
    if error:
        mensaje, codigo = error
        return jsonify({"status": "error", "mensaje": mensaje}), codigo

    config_ref = db.collection("configuracion_yape").document(usuario)
    config_doc = config_ref.get()
    if not config_doc.exists:
        return jsonify({
            "status": "error",
            "mensaje": "No hay un QR guardado para reactivar. Primero registra una imagen."
        }), 404

    config = config_doc.to_dict() or {}
    storage_path = str(config.get("storage_path") or "").strip()
    if not storage_path:
        return jsonify({
            "status": "error",
            "mensaje": "No se encontró la imagen guardada. Debes registrar nuevamente el QR."
        }), 404

    try:
        # Comprobar que el archivo privado todavía existe antes de reactivarlo.
        imagen = _supabase_descargar_qr(storage_path)
        if not imagen:
            return jsonify({
                "status": "error",
                "mensaje": "La imagen guardada no está disponible. Sube nuevamente el QR."
            }), 404

        config_ref.update({
            "activo": True,
            "habilitado_para_cobros": False,
            "validacion": "pendiente",
            "reactivado_en": firestore.SERVER_TIMESTAMP,
            "actualizado_en": firestore.SERVER_TIMESTAMP
        })
        return jsonify({
            "status": "ok",
            "mensaje": "El QR guardado fue reactivado. Los cobros siguen deshabilitados hasta completar su validación.",
            "qr_configurado": True,
            "qr_registrado": True,
            "qr_activo": True,
            "qr_estado": "activo",
            "habilitado_para_cobros": False
        }), 200
    except RuntimeError:
        app.logger.exception("No se pudo comprobar el QR en Supabase antes de reactivarlo.")
        return jsonify({
            "status": "error",
            "mensaje": "No se pudo verificar la imagen en el almacenamiento privado. El QR permanece desactivado."
        }), 503
    except Exception:
        app.logger.exception("Error al reactivar el QR del propietario %s.", usuario)
        return jsonify({
            "status": "error",
            "mensaje": "No se pudo reactivar el QR. El estado anterior se conserva."
        }), 503


@app.route("/api/propietario/maquinas/<id_caja>/configurar_servicio", methods=["POST"])
def propietario_configurar_servicio(id_caja):
    """Permite al propietario configurar segundos de servicio por cada S/1.00."""
    datos = request.get_json(silent=True) or {}
    usuario = str(datos.get("usuario") or "").strip()
    password_actual = str(datos.get("password_actual") or "")

    try:
        segundos_por_sol = int(datos.get("segundos_por_sol"))
    except (TypeError, ValueError):
        return jsonify({
            "status": "error",
            "mensaje": "Indica un tiempo válido en segundos por cada S/1.00."
        }), 400

    if not usuario or not password_actual:
        return jsonify({
            "status": "error",
            "mensaje": "Se requiere la cuenta del propietario y su contraseña actual."
        }), 400

    if not 1 <= segundos_por_sol <= 3600:
        return jsonify({
            "status": "error",
            "mensaje": "El tiempo debe estar entre 1 y 3600 segundos por cada S/1.00."
        }), 400

    cliente_ref = db.collection("clientes").document(usuario)
    cliente_doc = cliente_ref.get()
    if not cliente_doc.exists:
        return jsonify({"status": "error", "mensaje": "No se encontró la cuenta del propietario."}), 404

    cliente = cliente_doc.to_dict() or {}
    # Compatibilidad con propietarios antiguos: algunos registros pueden no
    # tener el campo "rol" o conservar el valor historico "cliente".
    rol_cliente = str(cliente.get("rol") or "propietario").strip().lower()
    if rol_cliente not in ("propietario", "cliente"):
        return jsonify({"status": "error", "mensaje": "Esta cuenta no corresponde a un propietario."}), 403
    if cliente.get("aprobado", False) is not True:
        return jsonify({"status": "error", "mensaje": "La cuenta todavía no está habilitada por TECSOL."}), 403

    password_guardada = cliente.get("password", "")
    if not _verificar_password(password_guardada, password_actual):
        return jsonify({"status": "error", "mensaje": "La contraseña actual es incorrecta."}), 401

    caja_ref = db.collection("cajas").document(id_caja)
    caja_doc = caja_ref.get()
    if not caja_doc.exists:
        return jsonify({"status": "error", "mensaje": "No se encontró la máquina."}), 404

    caja = caja_doc.to_dict() or {}
    if str(caja.get("propietario") or "") != usuario:
        return jsonify({"status": "error", "mensaje": "No puedes configurar una máquina que no pertenece a tu local."}), 403

    _migrar_password_si_antigua(cliente_ref, password_guardada)
    if rol_cliente != "propietario":
        cliente_ref.update({"rol": "propietario"})
    caja_ref.update({
        "segundos_por_sol": segundos_por_sol,
        "servicio_configurado": True,
        "servicio_actualizado": firestore.SERVER_TIMESTAMP
    })
    emitir_actualizacion_cajas()

    return jsonify({
        "status": "ok",
        "mensaje": "La configuración del servicio se guardó correctamente.",
        "id_caja": id_caja,
        "segundos_por_sol": segundos_por_sol
    }), 200


@app.route("/api/cliente/cambiar_password", methods=["POST"])
def cliente_cambiar_password():
    datos = request.get_json(silent=True) or {}
    usuario = str(datos.get("usuario") or "").strip()
    password_actual = str(datos.get("password_actual") or "")
    nuevo_password = str(datos.get("nuevo_password") or "")

    cliente_ref = db.collection("clientes").document(usuario)
    cliente_doc = cliente_ref.get()
    if not cliente_doc.exists:
        return jsonify({"status": "error"}), 404

    cliente = cliente_doc.to_dict() or {}
    if not _verificar_password(cliente.get("password", ""), password_actual):
        return jsonify({"status": "error", "mensaje": "Contraseña incorrecta"}), 401
    if len(nuevo_password) < 6:
        return jsonify({"status": "error", "mensaje": "La nueva contraseña debe tener al menos 6 caracteres."}), 400

    cliente_ref.update({"password": _crear_hash_password(nuevo_password)})
    return jsonify({"status": "ok"})


@app.route("/api/cajas", methods=["GET"])
def obtener_cajas():
    return jsonify(convertir_valores_para_json(obtener_cajas_db()))


@app.route("/api/publico/maquinas", methods=["GET"])
def obtener_maquinas_publicas():
    """Catálogo público agrupable por autolavado, estación y máquina.

    Solo devuelve máquinas habilitadas, asignadas a un propietario y vinculadas
    a una estación activa del mismo propietario. No expone ganancias, historial,
    contraseñas, hashes ni datos privados de los perfiles.
    """
    maquinas = []
    clientes = obtener_clientes_db()

    # Índice de estaciones activas para resolver la relación sin hacer una
    # consulta adicional por cada máquina.
    estaciones_activas = {}
    for estacion_doc in db.collection("estaciones").stream():
        estacion_datos = estacion_doc.to_dict() or {}
        if estacion_datos.get("activo", True) is not True:
            continue
        estaciones_activas[estacion_doc.id] = estacion_datos

    for doc in db.collection("cajas").stream():
        datos = doc.to_dict() or {}
        propietario = str(datos.get("propietario") or "sin_asignar").strip()
        tipo = str(datos.get("tipo") or "No asignado").strip()
        estacion_id = str(datos.get("estacion_id") or "").strip()

        # No exponer máquinas suspendidas, no asignadas o sin estación física.
        if datos.get("activo", True) is not True:
            continue
        if propietario == "sin_asignar" or tipo.lower() == "no asignado":
            continue
        if not estacion_id:
            continue

        perfil_propietario = clientes.get(propietario)
        if not isinstance(perfil_propietario, dict) or perfil_propietario.get("aprobado", False) is not True:
            continue

        estacion = estaciones_activas.get(estacion_id)
        if not isinstance(estacion, dict):
            continue
        if str(estacion.get("propietario") or "").strip() != propietario:
            # Evita que un error de configuración mezcle estaciones de distintos dueños.
            continue

        nombre_local = str(
            perfil_propietario.get("nombre_local") or propietario
        ).strip() or propietario
        nombre_estacion = str(estacion.get("nombre") or "Estación sin nombre").strip()

        try:
            segundos_por_sol = int(datos.get("segundos_por_sol") or 0)
        except (TypeError, ValueError):
            segundos_por_sol = 0

        maquinas.append({
            "id": doc.id,
            "nombre": str(datos.get("nombre") or "Máquina sin nombre"),
            "tipo": tipo,
            "propietario": propietario,
            "nombre_local": nombre_local,
            "estacion_id": estacion_id,
            "estacion_nombre": nombre_estacion,
            "conectado": _esp32_esta_conectado(datos),
            "segundos_por_sol": segundos_por_sol,
            "servicio_configurado": 1 <= segundos_por_sol <= 3600
        })

    maquinas.sort(key=lambda item: (
        item["nombre_local"].casefold(),
        item["propietario"].casefold(),
        item["estacion_nombre"].casefold(),
        item["tipo"].casefold(),
        item["nombre"].casefold()
    ))
    return jsonify({"maquinas": maquinas}), 200


@app.route("/api/consumidor/ordenes", methods=["POST"])
def consumidor_crear_orden_servicio():
    """Registra la selección de un crédito sin cobrar ni activar la máquina.

    El servidor vuelve a validar propietario, estación, licencia, heartbeat y
    tiempo por sol directamente en Firestore. Los importes permitidos son S/1,
    S/2 y S/3. La orden queda preparada para la futura integración de Yape.
    """
    usuario = _consumidor_autorizado()
    if not usuario:
        return jsonify({
            "status": "error",
            "mensaje": "Tu sesión venció o no es válida. Cierra sesión e ingresa nuevamente."
        }), 401

    datos = request.get_json(silent=True) or {}
    id_caja = str(datos.get("id_caja") or "").strip()
    request_id = str(datos.get("request_id") or "").strip()
    importe_recibido = datos.get("importe")

    if not id_caja:
        return jsonify({"status": "error", "mensaje": "No se indicó la máquina seleccionada."}), 400
    if not re.fullmatch(r"[A-Za-z0-9_-]{10,100}", request_id):
        return jsonify({"status": "error", "mensaje": "El identificador de selección no es válido."}), 400
    if isinstance(importe_recibido, bool):
        return jsonify({
            "status": "error",
            "mensaje": f"El importe debe ser un número entero entre S/ {CREDITO_MINIMO_SOLES}.00 y S/ {CREDITO_MAXIMO_SOLES}.00."
        }), 400
    try:
        importe_decimal = Decimal(str(importe_recibido))
    except (InvalidOperation, ValueError, TypeError):
        return jsonify({"status": "error", "mensaje": "El importe seleccionado no es válido."}), 400
    if (not importe_decimal.is_finite()
            or importe_decimal != importe_decimal.to_integral_value()
            or importe_decimal < CREDITO_MINIMO_SOLES
            or importe_decimal > CREDITO_MAXIMO_SOLES):
        return jsonify({
            "status": "error",
            "mensaje": f"Por ahora solo puedes seleccionar importes enteros entre S/ {CREDITO_MINIMO_SOLES}.00 y S/ {CREDITO_MAXIMO_SOLES}.00."
        }), 400
    importe = int(importe_decimal)

    consumidor_ref = db.collection("consumidores").document(usuario)
    consumidor_doc = consumidor_ref.get()
    if not consumidor_doc.exists:
        return jsonify({"status": "error", "mensaje": "No se encontró la cuenta del consumidor."}), 404
    consumidor = consumidor_doc.to_dict() or {}
    if consumidor.get("activo", True) is not True:
        return jsonify({"status": "error", "mensaje": "La cuenta de consumidor está desactivada."}), 403

    caja_ref = db.collection("cajas").document(id_caja)
    caja_doc = caja_ref.get()
    if not caja_doc.exists:
        return jsonify({"status": "error", "mensaje": "La máquina seleccionada ya no existe."}), 404
    caja = caja_doc.to_dict() or {}

    if caja.get("activo", True) is not True:
        return jsonify({"status": "error", "mensaje": "La máquina tiene la licencia suspendida y no está disponible."}), 409

    propietario = str(caja.get("propietario") or "").strip()
    estacion_id = str(caja.get("estacion_id") or "").strip()
    tipo_servicio = str(caja.get("tipo") or "No asignado").strip()
    if not propietario or propietario == "sin_asignar" or not estacion_id:
        return jsonify({"status": "error", "mensaje": "La máquina no tiene propietario y estación correctamente asignados."}), 409
    if tipo_servicio.casefold() == "no asignado":
        return jsonify({"status": "error", "mensaje": "La máquina todavía no tiene un servicio configurado."}), 409

    propietario_doc = db.collection("clientes").document(propietario).get()
    if not propietario_doc.exists:
        return jsonify({"status": "error", "mensaje": "No se encontró el propietario de la máquina."}), 409
    perfil_propietario = propietario_doc.to_dict() or {}
    if perfil_propietario.get("aprobado", False) is not True:
        return jsonify({"status": "error", "mensaje": "El establecimiento no está habilitado por TECSOL."}), 409

    estacion_doc = db.collection("estaciones").document(estacion_id).get()
    if not estacion_doc.exists:
        return jsonify({"status": "error", "mensaje": "La estación asignada ya no existe."}), 409
    estacion = estacion_doc.to_dict() or {}
    if (estacion.get("activo", True) is not True
            or str(estacion.get("propietario") or "").strip() != propietario):
        return jsonify({"status": "error", "mensaje": "La estación está deshabilitada o no pertenece a este propietario."}), 409

    if not _esp32_esta_conectado(caja):
        return jsonify({"status": "error", "mensaje": "La máquina perdió comunicación con su ESP32. Actualiza el catálogo e inténtalo nuevamente."}), 409

    try:
        segundos_por_sol = int(caja.get("segundos_por_sol") or 0)
    except (TypeError, ValueError):
        segundos_por_sol = 0
    if not 1 <= segundos_por_sol <= 3600:
        return jsonify({"status": "error", "mensaje": "El propietario todavía no ha configurado el tiempo de este servicio."}), 409

    duracion_segundos = segundos_por_sol * importe
    nombre_local = str(perfil_propietario.get("nombre_local") or propietario).strip() or propietario
    nombre_estacion = str(estacion.get("nombre") or caja.get("estacion_nombre") or "Estación").strip()
    nombre_maquina = str(caja.get("nombre") or "Máquina sin nombre").strip()

    # El ID determinista por consumidor y request_id hace que repetir el POST
    # no cree varias órdenes para un mismo toque del botón.
    orden_id = hashlib.sha256(f"{usuario}|{request_id}".encode("utf-8")).hexdigest()
    orden_ref = db.collection("ordenes_servicio").document(orden_id)
    orden_existente = orden_ref.get()
    if orden_existente.exists:
        anterior = orden_existente.to_dict() or {}
        if (anterior.get("consumidor") != usuario
                or anterior.get("id_caja") != id_caja
                or anterior.get("importe") != importe):
            return jsonify({"status": "error", "mensaje": "El identificador de selección ya fue utilizado para otra operación."}), 409
        return jsonify({
            "status": "ok",
            "mensaje": "La selección ya estaba registrada.",
            "orden_id": orden_id,
            "importe": anterior.get("importe"),
            "duracion_segundos": anterior.get("duracion_segundos"),
            "estado": anterior.get("estado", "seleccion_confirmada"),
            "repetida": True
        }), 200

    vence_en = datetime.now(timezone.utc) + timedelta(minutes=10)
    orden_ref.set({
        "orden_id": orden_id,
        "request_id": request_id,
        "consumidor": usuario,
        "nombre_consumidor": str(consumidor.get("nombre") or usuario),
        "propietario": propietario,
        "nombre_local": nombre_local,
        "estacion_id": estacion_id,
        "estacion_nombre": nombre_estacion,
        "id_caja": id_caja,
        "nombre_maquina": nombre_maquina,
        "tipo_servicio": tipo_servicio,
        "importe": importe,
        "segundos_por_sol": segundos_por_sol,
        "duracion_segundos": duracion_segundos,
        "estado": "seleccion_confirmada",
        "pago_estado": "no_iniciado",
        "activacion_autorizada": False,
        "activacion_enviada": False,
        "creado_en": firestore.SERVER_TIMESTAMP,
        "vence_en": vence_en
    })

    return jsonify({
        "status": "ok",
        "mensaje": "La selección fue registrada. Todavía no se ha realizado ningún pago.",
        "orden_id": orden_id,
        "importe": importe,
        "segundos_por_sol": segundos_por_sol,
        "duracion_segundos": duracion_segundos,
        "estado": "seleccion_confirmada",
        "pago_estado": "no_iniciado",
        "vence_en": vence_en.isoformat(),
        "repetida": False
    }), 201


@app.route("/api/cajas/<id_caja>/historial", methods=["GET"])
def obtener_historial(id_caja):
    ref = db.collection("cajas").document(id_caja).collection("historial").stream()
    reporte_dias = {}
    for doc in ref:
        data = doc.to_dict() or {}
        fecha = data.get("fecha")
        monto = data.get("monto", 0.0)
        if fecha:
            reporte_dias[fecha] = reporte_dias.get(fecha, 0.0) + float(monto or 0.0)
    return jsonify(reporte_dias)


@app.route("/api/cajas/<id_caja>", methods=["PUT"])
def actualizar_caja(id_caja):
    datos = request.get_json(silent=True) or {}
    caja_ref = db.collection("cajas").document(id_caja)
    caja_doc = caja_ref.get()

    if not caja_doc.exists:
        return jsonify({"status": "error", "mensaje": "Caja no encontrada"}), 404

    update_data = {}
    for campo in ("nombre", "tipo", "activo", "propietario"):
        if campo in datos:
            update_data[campo] = datos[campo]

    # Mantener un estado informativo para los dispositivos recién registrados.
    if "propietario" in update_data:
        propietario = str(update_data["propietario"] or "sin_asignar")
        update_data["estado_registro"] = (
            "asignada" if propietario != "sin_asignar" else "pendiente"
        )

    if update_data:
        caja_ref.update(update_data)

    emitir_actualizacion_cajas()
    return jsonify({"status": "ok"})


@app.route("/api/cajas/<id_caja>/reset", methods=["POST"])
def reiniciar_caja(id_caja):
    caja_ref = db.collection("cajas").document(id_caja)
    if not caja_ref.get().exists:
        return jsonify({"status": "error"}), 404

    # Reiniciar contadores sin borrar la subcolección historial.
    caja_ref.update({"monedas": 0, "yape": 0.0})
    emitir_actualizacion_cajas()
    return jsonify({"status": "ok"})


# --- REGISTRO AUTOMATICO DE ESP32 ---
@app.route("/api/dispositivos/registrar", methods=["POST"])
def registrar_dispositivo():
    datos = request.get_json(silent=True) or {}
    id_caja = str(datos.get("id_caja") or "").strip()
    mac = str(datos.get("mac") or "").strip().upper()

    # La MAC debe tener formato AA:BB:CC:DD:EE:FF.
    if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
        return jsonify({"status": "error", "mensaje": "MAC inválida"}), 400

    # Se acepta una ID manual para conservar una caja ya existente (ej. caja_1)
    # o la propia MAC como ID para cada ESP32 nuevo.
    if not id_caja or not re.fullmatch(r"[A-Za-z0-9:_-]{1,80}", id_caja):
        return jsonify({"status": "error", "mensaje": "id_caja inválido"}), 400

    caja_ref = db.collection("cajas").document(id_caja)
    caja_doc = caja_ref.get()
    ahora = firestore.SERVER_TIMESTAMP

    if caja_doc.exists:
        # No sobrescribir nombre, tipo, propietario, licencia ni ganancias existentes.
        caja_ref.set({
            "id": id_caja,
            "mac": mac,
            "ultima_conexion": ahora
        }, merge=True)
        creado = False
        mensaje = "Dispositivo existente actualizado; configuración conservada."
        codigo = 200
    else:
        # Nuevo ESP32: queda visible para el administrador, sin asignar y desactivado.
        caja_ref.set({
            "id": id_caja,
            "mac": mac,
            "nombre": "Nueva caja",
            "tipo": "No asignado",
            "monedas": 0,
            "yape": 0.0,
            "activo": False,
            "propietario": "sin_asignar",
            "estado_registro": "pendiente",
            "fecha_registro": ahora,
            "ultima_conexion": ahora
        })
        creado = True
        mensaje = "Nuevo dispositivo registrado y pendiente de asignación por TECSOL."
        codigo = 201

    emitir_actualizacion_cajas()
    return jsonify({
        "status": "ok",
        "nuevo": creado,
        "id_caja": id_caja,
        "mac": mac,
        "mensaje": mensaje
    }), codigo


@app.route("/api/dispositivos/heartbeat", methods=["POST"])
def heartbeat_dispositivo():
    """Registra que el ESP32 sigue activo y comunicandose con Render."""
    datos = request.get_json(silent=True) or {}
    id_caja = str(datos.get("id_caja") or "").strip()
    mac = str(datos.get("mac") or "").strip().upper()

    if not id_caja or not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
        return jsonify({"status": "error", "mensaje": "id_caja o MAC inválida"}), 400

    caja_ref = db.collection("cajas").document(id_caja)
    caja_doc = caja_ref.get()
    if not caja_doc.exists:
        return jsonify({"status": "error", "mensaje": "Dispositivo no registrado"}), 404

    datos_caja = caja_doc.to_dict() or {}
    mac_guardada = str(datos_caja.get("mac") or "").strip().upper()
    if mac_guardada and mac_guardada != mac:
        return jsonify({"status": "error", "mensaje": "La MAC no coincide con el dispositivo registrado"}), 403

    caja_ref.update({
        "mac": mac,
        "ultima_conexion": firestore.SERVER_TIMESTAMP
    })

    emitir_actualizacion_cajas()
    return jsonify({"status": "ok", "id_caja": id_caja, "conectado": True}), 200


@app.route("/ingresar_moneda", methods=["POST"])
def ingresar_moneda():
    datos = request.get_json(silent=True) or {}
    id_caja = str(datos.get("id_caja") or "").strip()
    mac = str(datos.get("mac") or "").strip().upper()

    if not id_caja:
        return jsonify({"status": "error", "mensaje": "Falta id_caja"}), 400

    # Fecha local de Perú (UTC-5), manteniendo el formato histórico actual.
    fecha_hoy = (datetime.utcnow() + timedelta(hours=-5)).strftime("%Y-%m-%d")
    caja_ref = db.collection("cajas").document(id_caja)
    caja_doc = caja_ref.get()

    if not caja_doc.exists:
        # Compatibilidad: si el primer registro de dispositivo no llegó al iniciar,
        # la primera moneda crea una caja pendiente y conserva ese ingreso.
        caja_ref.set({
            "id": id_caja,
            "mac": mac if re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac) else None,
            "nombre": "Nueva caja",
            "tipo": "No asignado",
            "monedas": 1,
            "yape": 0.0,
            "activo": False,
            "propietario": "sin_asignar",
            "estado_registro": "pendiente",
            "fecha_registro": firestore.SERVER_TIMESTAMP,
            "ultima_conexion": firestore.SERVER_TIMESTAMP
        })
    else:
        caja_ref.update({
            "monedas": firestore.Increment(1),
            "ultima_conexion": firestore.SERVER_TIMESTAMP
        })

    caja_ref.collection("historial").add({
        "fecha": fecha_hoy,
        "monto": 1.0,
        "tipo": "moneda"
    })

    emitir_actualizacion_cajas()
    return jsonify({"status": "ok", "id_caja": id_caja, "monto": 1.0}), 200


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
