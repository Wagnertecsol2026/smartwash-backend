from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
from datetime import datetime, timedelta
import firebase_admin
from firebase_admin import credentials, firestore
import os
import json

app = Flask(__name__)

# Permitir la web publicada y los puertos locales de Flutter Web.
CORS(app, origins=[
    "https://smartwashtecsol.web.app",
    r"^http://localhost:\d+$",
    r"^http://127\.0\.0\.1:\d+$"
])

# Usar threading en lugar de Eventlet.
# simple-websocket permite mantener WebSockets con este modo.
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)

# --- INICIALIZAR FIREBASE SEGURO ---
firebase_env = os.environ.get("FIREBASE_CONFIG_JSON")

if firebase_env:
    # En Render, leer la cuenta de servicio desde una variable secreta.
    cred_dict = json.loads(firebase_env)
    cred = credentials.Certificate(cred_dict)
else:
    # En la laptop, utilizar el archivo local firebase_key.json.
    cred = credentials.Certificate("firebase_key.json")

firebase_admin.initialize_app(cred)
db = firestore.client()

ADMIN_MASTER_USER = os.environ.get("ADMIN_MASTER_USER", "admin")
# Configurar ADMIN_MASTER_PASS en las variables de entorno de Render.
# No guardar la contraseña maestra dentro del código fuente.
ADMIN_MASTER_PASS = os.environ.get("ADMIN_MASTER_PASS", "")


# --- FUNCIONES DE APOYO PARA SINCRONIZAR CON FIRESTORE ---
def obtener_clientes_db():
    docs = db.collection("clientes").stream()
    return {doc.id: doc.to_dict() for doc in docs}


def obtener_cajas_db():
    docs = db.collection("cajas").stream()
    return {doc.id: doc.to_dict() for doc in docs}


# --- RUTAS DE LA API ---

@app.route("/api/registro", methods=["POST"])
def registrar_cliente():
    datos = request.get_json() or {}
    usuario = datos.get("usuario")
    password = datos.get("password")

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
    })


@app.route("/api/login", methods=["POST"])
def login():
    datos = request.get_json() or {}
    usuario = datos.get("usuario")
    password = datos.get("password")

    if (ADMIN_MASTER_PASS and usuario == ADMIN_MASTER_USER
            and password == ADMIN_MASTER_PASS):
        return jsonify({
            "status": "ok",
            "rol": "admin",
            "clientes": obtener_clientes_db()
        })
