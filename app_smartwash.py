from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
from datetime import datetime, timedelta
import firebase_admin
from firebase_admin import credentials, firestore
import os
import json
import re

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

# --- FUNCIONES DE APOYO ---
def obtener_clientes_db():
    docs = db.collection("clientes").stream()
    return {doc.id: doc.to_dict() for doc in docs}


def obtener_cajas_db():
    """Devuelve las cajas y garantiza que cada objeto incluya su ID de documento."""
    resultado = {}
    for doc in db.collection("cajas").stream():
        datos = doc.to_dict() or {}
        datos.setdefault("id", doc.id)
        resultado[doc.id] = datos
    return resultado


def emitir_actualizacion_cajas():
    socketio.emit("actualizacion_cajas", obtener_cajas_db())


# --- RUTAS DE LA API ---

@app.route("/api/registro", methods=["POST"])
def registrar_cliente():
    datos = request.get_json(silent=True) or {}
    usuario = str(datos.get("usuario") or "").strip()
    password = str(datos.get("password") or "")

    if not usuario or not password:
        return jsonify({"status": "error", "mensaje": "Faltan datos"}), 400

    clientes = obtener_clientes_db()
    if usuario in clientes or usuario == ADMIN_MASTER_USER:
        return jsonify({"status": "error", "mensaje": "El usuario ya existe"}), 400

    db.collection("clientes").document(usuario).set({
        "password": password,
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
            "clientes": obtener_clientes_db()
        }), 200

    clientes = obtener_clientes_db()
    cliente = clientes.get(usuario)

    if cliente is None or cliente.get("password") != password:
        return jsonify({"status": "error", "mensaje": "Credenciales incorrectas"}), 401

    if not cliente.get("aprobado", False):
        return jsonify({
            "status": "error",
            "mensaje": "Cuenta pendiente de activación por TECSOL."
        }), 403

    return jsonify({
        "status": "ok",
        "rol": "cliente",
        "usuario": usuario
    }), 200


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
        cliente_ref.update({"password": nuevo_password})
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
    if cliente.get("password") != password_actual:
        return jsonify({"status": "error", "mensaje": "Contraseña incorrecta"}), 401
    if not nuevo_password:
        return jsonify({"status": "error", "mensaje": "Falta la nueva contraseña"}), 400

    cliente_ref.update({"password": nuevo_password})
    return jsonify({"status": "ok"})


@app.route("/api/cajas", methods=["GET"])
def obtener_cajas():
    return jsonify(obtener_cajas_db())


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
