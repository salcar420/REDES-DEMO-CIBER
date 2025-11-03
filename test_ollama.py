import requests

url = "http://127.0.0.1:11434/api/generate"
payload = {"model":"mistral","prompt":"Dime 3 consejos para aprender inglés rápido","stream":False}
r = requests.post(url, json=payload, headers={"Content-Type":"application/json"})
print("status:", r.status_code)
print(r.text)
