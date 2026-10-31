import eventlet
eventlet.monkey_patch()

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
import uuid

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# --- CREDENCIALES Y ROLES COMERCIALES ---
ADMIN_MASTER_USER = "admin"
ADMIN_MASTER_PASS = "tecsol2026"

# Base de datos de clientes comerciales (Puedes registrar aquí a tus compradores)
CLIENTES_DB = {
    "cliente_express": {
        "password": "password123",
        "cajas_asignadas": [] # Aquí puedes filtrar cajas específicas si deseas, o dejarlo abierto
    }
}

cajas_tecsol = {}

# --- NUEVA RUTA DE LOGIN CON ROLES ---
@app.route('/api/login', methods=['POST'])
def login():
    datos = request.get_json() or {}
    usuario = datos.get("usuario")
    password = datos.get("password")

    # 1. Acceso Administrador Maestro (Tú - TECSOL)
    if usuario == ADMIN_MASTER_USER and password == ADMIN_MASTER_PASS:
        return jsonify({"status": "ok", "rol": "admin", "mensaje": "Acceso Maestro TECSOL"})

    # 2. Acceso Cliente Final (Dueño del Car Wash)
    if usuario in CLIENTES_DB and CLIENTES_DB[usuario]["password"] == password:
        return jsonify({
            "status": "ok",
            "rol": "cliente",
            "usuario": usuario,
            "cajas_asignadas": CLIENTES_DB[usuario]["cajas_asignadas"],
            "mensaje": "Acceso Cliente"
        })

    return jsonify({"status": "error", "mensaje": "Credenciales incorrectas"}), 401

@app.route('/api/cajas', methods=['GET'])
def obtener_cajas():
    return jsonify(cajas_tecsol)

@app.route('/api/cajas', methods=['POST'])
def agregar_caja():
    datos = request.get_json() or {}
    id_caja = f"caja_{str(uuid.uuid4())[:4]}"
    nueva_caja = {
        "id": id_caja,
        "nombre": datos.get("nombre", "Nueva Caja"),
        "tipo": datos.get("tipo", "Agua"),
        "monedas": 0,
        "yape": 0.0,
        "activo": True # Control de licencia/suscripción por defecto activo
    }
    cajas_tecsol[id_caja] = nueva_caja
    socketio.emit('actualizacion_cajas', cajas_tecsol)
    return jsonify(nueva_caja)

@app.route('/api/cajas/<id_caja>', methods=['PUT'])
def actualizar_caja(id_caja):
    datos = request.get_json() or {}
    if id_caja in cajas_tecsol:
        cajas_tecsol[id_caja]["nombre"] = datos.get("nombre", cajas_tecsol[id_caja]["nombre"])
        cajas_tecsol[id_caja]["tipo"] = datos.get("tipo", cajas_tecsol[id_caja]["tipo"])
        if 'activo' in datos:
            cajas_tecsol[id_caja]["activo"] = datos.get("activo")

        socketio.emit('actualizacion_cajas', cajas_tecsol)
        return jsonify({"status": "ok", "caja": cajas_tecsol[id_caja]})
    return jsonify({"status": "error", "mensaje": "Caja no encontrada"}), 404

@app.route('/api/cajas/<id_caja>/reset', methods=['POST'])
def reiniciar_caja(id_caja):
    if id_caja in cajas_tecsol:
        cajas_tecsol[id_caja]["monedas"] = 0
        cajas_tecsol[id_caja]["yape"] = 0.0
        socketio.emit('actualizacion_cajas', cajas_tecsol)
        return jsonify({"status": "ok", "caja": cajas_tecsol[id_caja]})
    return jsonify({"status": "error", "mensaje": "Caja no encontrada"}), 404

@app.route('/ingresar_moneda', methods=['POST'])
def ingresar_moneda():
    datos = request.get_json() or {}
    id_caja = datos.get("id_caja")
    if not id_caja:
        return jsonify({"status": "error", "mensaje": "ID no proporcionado"}), 400
    if id_caja not in cajas_tecsol:
        cajas_tecsol[id_caja] = {
            "id": id_caja,
            "nombre": "Nueva Caja Pendiente",
            "tipo": "No asignado",
            "monedas": 0,
            "yape": 0.0,
            "activo": True
        }
    cajas_tecsol[id_caja]["monedas"] += 1
    socketio.emit('actualizacion_cajas', cajas_tecsol)
    return jsonify({"status": "ok", "caja": cajas_tecsol[id_caja]})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
