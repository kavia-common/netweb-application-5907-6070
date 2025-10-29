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
- POST /devices — create device (requires id, name, ip_address, device_type, location)
- GET /devices/{id} — get device by id
- PUT /devices/{id} — update device fields (name, ip_address, device_type, location)
- DELETE /devices/{id} — delete device by id

Validation rules:
- id: unique integer
- name: non-empty string
- ip_address: IPv4 format
- device_type: one of [router, switch, server]
- location: non-empty string
