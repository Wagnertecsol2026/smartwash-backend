import eventlet
eventlet.monkey_patch()

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
import uuid


app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# --- CREDENCIALES DE ADMINISTRADOR ---
USUARIO_ADMIN = "admin"
PASSWORD_ADMIN = "tecsol2026"

cajas_tecsol = {}

# --- NUEVA RUTA DE LOGIN ---
@app.route('/api/login', methods=['POST'])
def login():
    datos = request.get_json() or {}
    usuario = datos.get("usuario")
    password = datos.get("password")

    if usuario == USUARIO_ADMIN and password == PASSWORD_ADMIN:
        return jsonify({"status": "ok", "mensaje": "Acceso permitido"})
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
        "yape": 0.0
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
            "yape": 0.0
        }
    cajas_tecsol[id_caja]["monedas"] += 1
    socketio.emit('actualizacion_cajas', cajas_tecsol)
    return jsonify({"status": "ok", "caja": cajas_tecsol[id_caja]})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
