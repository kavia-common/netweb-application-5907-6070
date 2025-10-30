# netweb-application-5907-6070

## Flask Backend (NetWeb Device Management API)

Prerequisites:
- Python 3.10+
- MongoDB accessible via connection string
- Create a `.env` file inside `FlaskBackend/` based on `.env.example`

Setup and run:
1. cd FlaskBackend
2. python -m venv .venv && source .venv/bin/activate  (Windows: .venv\Scripts\activate)
3. pip install -r requirements.txt
4. cp .env.example .env  (then edit values as needed)
5. python run.py

Environment variables (set in `FlaskBackend/.env`):
- MONGODB_URI
- MONGODB_DB_NAME
- MONGODB_COLLECTION_NAME

OpenAPI/Swagger UI:
- Available at /docs on the running backend (e.g., http://localhost:5000/docs)

API summary:
- GET /devices — list devices
- POST /devices — create device (requires name, ip_address, device_type, location)
- GET /devices/{name} — get device by unique name
- PUT /devices/{name} — update device fields (name, ip_address, device_type, location) and optionally rename
- DELETE /devices/{name} — delete device by unique name

Validation rules:
- name: non-empty string (unique)
- ip_address: IPv4 format
- device_type: one of [router, switch, server]
- location: non-empty string
