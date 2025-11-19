import requests
from flask import jsonify

def PostRequestVuln(api, model, prompt):
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False
    }
    try:
        r = requests.post(api, json=payload, headers={"Content-Type":"application/json"}, timeout=120)
    except Exception as e:
        return jsonify({"error": "No se pudo conectar con Ollama", "detail": str(e)}), 500

    # Solo devolver el texto útil al frontend
    try:
        data = r.json()
        text = data.get("response") or data.get("outputs") or data.get("result") or ""
        return jsonify({"respuesta": text})
    except Exception:
        return jsonify({"error":"Respuesta no válida desde Ollama", "raw": r.text}), r.status_code