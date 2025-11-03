# app_vulnerable.py  (USAR SOLO EN ENTORNO AISLADO PARA DEMO)
from flask import Flask, request, jsonify
import requests, os
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")

# NOTE: Este system_prompt se concatena directamente con la entrada del usuario -> vulnerable
SYSTEM_PROMPT = "Eres un asistente que debe seguir estas reglas: Responde brevemente y en español.\nInstrucción del usuario: "

@app.route("/ask_vuln", methods=["POST"])
def ask_vuln():
    body = request.get_json() or {}
    user_input = body.get("prompt", "")
    # Vulnerabilidad: concatenación directa sin sanitizar
    full_prompt = SYSTEM_PROMPT + user_input
    payload = {"model": "mistral", "prompt": full_prompt, "stream": False}
    try:
        r = requests.post(OLLAMA_URL, json=payload, headers={"Content-Type":"application/json"}, timeout=120)
    except Exception as e:
        return jsonify({"error":"No se pudo conectar con Ollama","detail": str(e)}), 500

    try:
        return jsonify(r.json()), r.status_code
    except Exception:
        return jsonify({"error":"Respuesta no JSON desde Ollama","raw": r.text}), r.status_code

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
