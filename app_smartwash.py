import eventlet
eventlet.monkey_patch()

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
import uuid

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# --- CREDENCIALES DE SUPER ADMIN ---
ADMIN_MASTER_USER = "admin"
ADMIN_MASTER_PASS = "tecsol2026"

# Base de datos en memoria para clientes registrados
# Estructura: "usuario": {"password": "...", "aprobado": True/False}
CLIENTES_REGISTRADOS = {}
cajas_tecsol = {}

# --- RUTA DE REGISTRO PARA NUEVOS CLIENTES ---
@app.route('/api/registro', methods=['POST'])
def registrar_cliente():
    datos = request.get_json() or {}
    usuario = datos.get("usuario")
    password = datos.get("password")
    
    if not usuario or not password:
        return jsonify({"status": "error", "mensaje": "Faltan datos"}), 400
        
    if usuario in CLIENTES_REGISTRADOS or usuario == ADMIN_MASTER_USER:
        return jsonify({"status": "error", "mensaje": "El usuario ya existe"}), 400
        
    CLIENTES_REGISTRADOS[usuario] = {
        "password": password,
        "aprobado": False # Pendiente de aprobación del Super Admin
    }
    
    return jsonify({"status": "ok", "mensaje": "Registro exitoso. Espere activación del administrador."})

# --- RUTA DE LOGIN ---
@app.route('/api/login', methods=['POST'])
def login():
    datos = request.get_json() or {}
    usuario = datos.get("usuario")
    password = datos.get("password")
    
    # 1. Super Admin
    if usuario == ADMIN_MASTER_USER and password == ADMIN_MASTER_PASS:
        return jsonify({"status": "ok", "rol": "admin", "clientes": CLIENTES_REGISTRADOS})
        
    # 2. Cliente Registrado
    if usuario in CLIENTES_REGISTRADOS:
        if CLIENTES_REGISTRADOS[usuario]["password"] == password:
            if not CLIENTES_REGISTRADOS[usuario]["aprobado"]:
                return jsonify({"status": "error", "mensaje": "Cuenta pendiente de activación por TECSOL."}), 403
            return jsonify({"status": "ok", "rol": "cliente", "usuario": usuario})
            
    return jsonify({"status": "error", "mensaje": "Credenciales incorrectas"}), 401

# --- RUTA PARA QUE EL ADMIN APRUEBE CLIENTES ---
@app.route('/api/admin/aprobar_cliente', methods=['POST'])
def aprobar_cliente():
    datos = request.get_json() or {}
    usuario = datos.get("usuario")
    estado = datos.get("aprobado", True)
    
    if usuario in CLIENTES_REGISTRADOS:
        CLIENTES_REGISTRADOS[usuario]["aprobado"] = estado
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "mensaje": "Cliente no encontrado"}), 404

# --- NUEVA RUTA: ADMIN CAMBIA CONTRASEÑA PROVISIONAL ---
@app.route('/api/admin/cambiar_password', methods=['POST'])
def admin_cambiar_password():
    datos = request.get_json() or {}
    usuario = datos.get("usuario")
    nuevo_password = datos.get("nuevo_password")
    
    if usuario in CLIENTES_REGISTRADOS and nuevo_password:
        CLIENTES_REGISTRADOS[usuario]["password"] = nuevo_password
        return jsonify({"status": "ok", "mensaje": "Contraseña actualizada por el Admin"})
    return jsonify({"status": "error", "mensaje": "Cliente no encontrado"}), 404

# --- NUEVA RUTA: CLIENTE CAMBIA SU PROPIA CONTRASEÑA ---
@app.route('/api/cliente/cambiar_password', methods=['POST'])
def cliente_cambiar_password():
    datos = request.get_json() or {}
    usuario = datos.get("usuario")
    password_actual = datos.get("password_actual")
    nuevo_password = datos.get("nuevo_password")
    
    if usuario in CLIENTES_REGISTRADOS:
        if CLIENTES_REGISTRADOS[usuario]["password"] == password_actual:
            CLIENTES_REGISTRADOS[usuario]["password"] = nuevo_password
            return jsonify({"status": "ok", "mensaje": "Contraseña actualizada con éxito"})
        else:
            return jsonify({"status": "error", "mensaje": "La contraseña actual es incorrecta"}), 401
    return jsonify({"status": "error", "mensaje": "Usuario no encontrado"}), 404

@app.route('/api/cajas', methods=['GET'])
def obtener_cajas():
    return jsonify(cajas_tecsol)

@app.route('/api/cajas/<id_caja>', methods=['PUT'])
def actualizar_caja(id_caja):
    datos = request.get_json() or {}
    if id_caja in cajas_tecsol:
        cajas_tecsol[id_caja]["nombre"] = datos.get("nombre", cajas_tecsol[id_caja]["nombre"])
        cajas_tecsol[id_caja]["tipo"] = datos.get("tipo", cajas_tecsol[id_caja]["tipo"])
        if 'activo' in datos:
            cajas_tecsol[id_caja]["activo"] = datos.get("activo")
        if 'propietario' in datos:
            cajas_tecsol[id_caja]["propietario"] = datos.get("propietario")
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
            "nombre": "Caja Nueva",
            "tipo": "Agua",
            "monedas": 0,
            "yape": 0.0,
            "activo": True,
            "propietario": "sin_asignar"
        }
    cajas_tecsol[id_caja]["monedas"] += 1
    socketio.emit('actualizacion_cajas', cajas_tecsol)
    return jsonify({"status": "ok", "caja": cajas_tecsol[id_caja]})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
