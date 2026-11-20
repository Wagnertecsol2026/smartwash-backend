from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
from datetime import datetime, timedelta, date, timezone
import firebase_admin
from firebase_admin import credentials, firestore
import os
import json
import re
import hashlib
import hmac
import secrets

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
        # Nombre inicial del local. El nombre comercial personalizado podrá
        # mantenerse aquí en una actualización posterior autenticada.
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

        return jsonify({
            "status": "ok",
            "rol": "admin",
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

        return jsonify({
            "status": "ok",
            "rol": "propietario",
            "usuario": usuario,
            "nombre_local": cliente.get("nombre_local") or usuario
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
        return jsonify({
            "status": "ok",
            "rol": "consumidor",
            "usuario": usuario,
            "nombre": consumidor.get("nombre") or usuario
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
    """Catálogo público mínimo agrupable por local; no devuelve ganancias ni historial."""
    maquinas = []

    # Se consulta la colección una sola vez para resolver el nombre público
    # del local sin exponer contraseñas, hashes, teléfonos ni datos internos.
    clientes = obtener_clientes_db()

    for doc in db.collection("cajas").stream():
        datos = doc.to_dict() or {}
        propietario = str(datos.get("propietario") or "sin_asignar")
        tipo = str(datos.get("tipo") or "No asignado")
        if datos.get("activo", True) is not True:
            continue
        if propietario == "sin_asignar" or tipo.strip().lower() == "no asignado":
            continue

        perfil_propietario = clientes.get(propietario, {}) or {}
        nombre_local = str(
            perfil_propietario.get("nombre_local") or propietario
        ).strip()

        maquinas.append({
            "id": doc.id,
            "nombre": str(datos.get("nombre") or "Máquina sin nombre"),
            "tipo": tipo,
            "propietario": propietario,
            "nombre_local": nombre_local or propietario,
            "conectado": _esp32_esta_conectado(datos)
        })

    maquinas.sort(key=lambda item: (
        item["nombre_local"].lower(),
        item["propietario"].lower(),
        item["tipo"].lower(),
        item["nombre"].lower()
    ))
    return jsonify({"maquinas": maquinas}), 200


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



