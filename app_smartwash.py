import eventlet
eventlet.monkey_patch()

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
from datetime import datetime, timedelta
import firebase_admin
from firebase_admin import credentials, firestore
import os
import json

app = Flask(__name__)
CORS(app, origins=["https://smartwashtecsol.web.app"])
socketio = SocketIO(app, cors_allowed_origins="*")

# --- INICIALIZAR FIREBASE SEGURO ---
firebase_env = os.environ.get("FIREBASE_CONFIG_JSON")

if firebase_env:
    # Si estamos en Render, lee la variable de entorno secreta
    cred_dict = json.loads(firebase_env)
    cred = credentials.Certificate(cred_dict)
else:
    # Si estamos en tu laptop, lee el archivo local 'firebase_key.json'
    cred = credentials.Certificate("firebase_key.json")

firebase_admin.initialize_app(cred)
db = firestore.client()

ADMIN_MASTER_USER = "admin"
ADMIN_MASTER_PASS = "tecsol2026"

# --- FUNCIONES DE APOYO PARA SINCRONIZAR CON FIRESTORE ---
def obtener_clientes_db():
    docs = db.collection('clientes').stream()
    return {doc.id: doc.to_dict() for doc in docs}

def obtener_cajas_db():
    docs = db.collection('cajas').stream()
    return {doc.id: doc.to_dict() for doc in docs}

# --- RUTAS DE LA API ---

@app.route('/api/registro', methods=['POST'])
def registrar_cliente():
    datos = request.get_json() or {}
    usuario = datos.get("usuario")
    password = datos.get("password")

    if not usuario or not password:
        return jsonify({"status": "error", "mensaje": "Faltan datos"}), 400

    clientes = obtener_clientes_db()
    if usuario in clientes or usuario == ADMIN_MASTER_USER:
        return jsonify({"status": "error", "mensaje": "El usuario ya existe"}), 400

    db.collection('clientes').document(usuario).set({
        "password": password,
        "aprobado": False
    })
    return jsonify({"status": "ok", "mensaje": "Registro exitoso. Espere activación del administrador."})

@app.route('/api/login', methods=['POST'])
def login():
    datos = request.get_json() or {}
    usuario = datos.get("usuario")
    password = datos.get("password")

    if usuario == ADMIN_MASTER_USER and password == ADMIN_MASTER_PASS:
        return jsonify({"status": "ok", "rol": "admin", "clientes": obtener_clientes_db()})

    clientes = obtener_clientes_db()
    if usuario in clientes:
        if clientes[usuario]["password"] == password:
            if not clientes[usuario]["aprobado"]:
                return jsonify({"status": "error", "mensaje": "Cuenta pendiente de activación por TECSOL."}), 403
            return jsonify({"status": "ok", "rol": "cliente", "usuario": usuario})

    return jsonify({"status": "error", "mensaje": "Credenciales incorrectas"}), 401

@app.route('/api/admin/aprobar_cliente', methods=['POST'])
def aprobar_cliente():
    datos = request.get_json() or {}
    usuario = datos.get("usuario")
    estado = datos.get("aprobado", True)

    clientes = obtener_clientes_db()
    if usuario in clientes:
        db.collection('clientes').document(usuario).update({"aprobado": estado})
        return jsonify({"status": "ok"})
    return jsonify({"status": "error"}), 404

@app.route('/api/admin/cambiar_password', methods=['POST'])
def admin_cambiar_password():
    datos = request.get_json() or {}
    usuario = datos.get("usuario")
    nuevo_password = datos.get("nuevo_password")

    clientes = obtener_clientes_db()
    if usuario in clientes and nuevo_password:
        db.collection('clientes').document(usuario).update({"password": nuevo_password})
        return jsonify({"status": "ok"})
    return jsonify({"status": "error"}), 404

@app.route('/api/cliente/cambiar_password', methods=['POST'])
def cliente_cambiar_password():
    datos = request.get_json() or {}
    usuario = datos.get("usuario")
    password_actual = datos.get("password_actual")
    nuevo_password = datos.get("nuevo_password")

    clientes = obtener_clientes_db()
    if usuario in clientes:
        if clientes[usuario]["password"] == password_actual:
            db.collection('clientes').document(usuario).update({"password": nuevo_password})
            return jsonify({"status": "ok"})
        else:
            return jsonify({"status": "error", "mensaje": "Contraseña incorrecta"}), 401
    return jsonify({"status": "error"}), 404

@app.route('/api/cajas', methods=['GET'])
def obtener_cajas():
    return jsonify(obtener_cajas_db())

@app.route('/api/cajas/<id_caja>/historial', methods=['GET'])
def obtener_historial(id_caja):
    ref = db.collection('cajas').document(id_caja).collection('historial').stream()
    reporte_dias = {}
    for doc in ref:
        data = doc.to_dict()
        fec = data.get("fecha")
        monto = data.get("monto", 0.0)
        reporte_dias[fec] = reporte_dias.get(fec, 0.0) + monto
    return jsonify(reporte_dias)

@app.route('/api/cajas/<id_caja>', methods=['PUT'])
def actualizar_caja(id_caja):
    datos = request.get_json() or {}
    cajas = obtener_cajas_db()

    if id_caja in cajas:
        update_data = {}
        if "nombre" in datos: update_data["nombre"] = datos["nombre"]
        if "tipo" in datos: update_data["tipo"] = datos["tipo"]
        if "activo" in datos: update_data["activo"] = datos["activo"]
        if "propietario" in datos: update_data["propietario"] = datos["propietario"]

        db.collection('cajas').document(id_caja).update(update_data)
        socketio.emit('actualizacion_cajas', obtener_cajas_db())
        return jsonify({"status": "ok"})
    return jsonify({"status": "error"}), 404

@app.route('/api/cajas/<id_caja>/reset', methods=['POST'])
def reiniciar_caja(id_caja):
    cajas = obtener_cajas_db()
    if id_caja in cajas:
        db.collection('cajas').document(id_caja).update({"monedas": 0, "yape": 0.0})

        # Limpiar historial al reiniciar contadores
        hist_ref = db.collection('cajas').document(id_caja).collection('historial').stream()
        for doc in hist_ref:
            doc.reference.delete()

        socketio.emit('actualizacion_cajas', obtener_cajas_db())
        return jsonify({"status": "ok"})
    return jsonify({"status": "error"}), 404

@app.route('/ingresar_moneda', methods=['POST'])
def ingresar_moneda():
    datos = request.get_json() or {}
    id_caja = datos.get("id_caja")
    if not id_caja:
        return jsonify({"status": "error"}), 400

    # Ajustar fecha a la hora local de Perú (UTC-5)
    zona_peru = timedelta(hours=-5)
    fecha_hoy = (datetime.utcnow() + zona_peru).strftime("%Y-%m-%d")

    caja_ref = db.collection('cajas').document(id_caja)
    caja_doc = caja_ref.get()

    if not caja_doc.exists:
        caja_ref.set({
            "id": id_caja,
            "nombre": "Caja Nueva",
            "tipo": "Agua",
            "monedas": 1,
            "yape": 0.0,
            "activo": True,
            "propietario": "sin_asignar"
        })
    else:
        caja_ref.update({
            "monedas": firestore.Increment(1)
        })

    # Registrar en la subcolección de historial con la fecha de Perú
    caja_ref.collection('historial').add({
        "fecha": fecha_hoy,
        "monto": 1.0,
        "tipo": "moneda"
    })

    socketio.emit('actualizacion_cajas', obtener_cajas_db())
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
