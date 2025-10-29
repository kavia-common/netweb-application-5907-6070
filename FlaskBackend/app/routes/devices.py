import logging
import os
import re
from typing import Any, Dict, List, Optional

from flask import request
from flask.views import MethodView
from flask_smorest import Blueprint

try:
    from pymongo import MongoClient, ASCENDING
    from pymongo.errors import PyMongoError
except Exception:  # pragma: no cover
    # Defer import error to runtime error message so the app can still load helpfully.
    MongoClient = None  # type: ignore
    PyMongoError = Exception  # type: ignore

# Configure module-level logger
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s [%(name)s] %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Create blueprint for devices
blp = Blueprint(
    "Devices",
    "devices",
    url_prefix="/devices",
    description="Operations related to device management",
)

# Validation helpers and schema constraints
DEVICE_TYPES = {"router", "switch", "server"}
IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _validate_ipv4(ip: str) -> bool:
    if not IPV4_PATTERN.match(ip):
        return False
    # Ensure each octet is 0-255
    parts = ip.split(".")
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _validate_device_payload(payload: Dict[str, Any], require_id: bool = True) -> Optional[Dict[str, List[str]]]:
    """
    Validates device payload.
    When require_id=True, ensures 'id' is present and integer.
    Returns None if valid, otherwise a dict of field->list(errors).
    """
    errors: Dict[str, List[str]] = {}

    # id
    if require_id:
        if "id" not in payload:
            errors.setdefault("id", []).append("Missing required field 'id'.")
        else:
            if not isinstance(payload["id"], int):
                errors.setdefault("id", []).append("Field 'id' must be an integer.")
    else:
        # In PUT body we do not require 'id' (id comes from path), but if present must be integer and match path (checked externally)
        if "id" in payload and not isinstance(payload["id"], int):
            errors.setdefault("id", []).append("Field 'id' must be an integer if provided.")

    # name
    if "name" not in payload or not isinstance(payload.get("name"), str) or not payload.get("name", "").strip():
        errors.setdefault("name", []).append("Field 'name' is required and must be a non-empty string.")

    # ip_address
    ip = payload.get("ip_address")
    if ip is None or not isinstance(ip, str) or not _validate_ipv4(ip):
        errors.setdefault("ip_address", []).append("Field 'ip_address' is required and must be a valid IPv4 address.")

    # device_type
    dtype = payload.get("device_type")
    if dtype is None or not isinstance(dtype, str) or dtype not in DEVICE_TYPES:
        errors.setdefault("device_type", []).append(f"Field 'device_type' is required and must be one of {sorted(DEVICE_TYPES)}.")

    # location
    if "location" not in payload or not isinstance(payload.get("location"), str) or not payload.get("location", "").strip():
        errors.setdefault("location", []).append("Field 'location' is required and must be a non-empty string.")

    return None if not errors else errors


def _mongo_collection():
    """
    Initializes and returns the MongoDB collection using environment variables.
    Required env vars:
      - MONGODB_URI
      - MONGODB_DB_NAME
      - MONGODB_COLLECTION_NAME
    """
    uri = os.getenv("MONGODB_URI")
    dbname = os.getenv("MONGODB_DB_NAME")
    collname = os.getenv("MONGODB_COLLECTION_NAME")

    if not uri or not dbname or not collname:
        missing = [n for n, v in [
            ("MONGODB_URI", uri),
            ("MONGODB_DB_NAME", dbname),
            ("MONGODB_COLLECTION_NAME", collname),
        ] if not v]
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

    if MongoClient is None:
        raise RuntimeError("pymongo is not installed. Please ensure it is added to requirements.txt and installed.")

    client = MongoClient(uri)
    db = client[dbname]
    coll = db[collname]
    # Ensure unique index on 'id'
    try:
        coll.create_index([("id", ASCENDING)], unique=True, background=True)
    except Exception as e:
        logger.warning("Could not ensure index on 'id': %s", e)
    return coll


def _sanitize(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Converts MongoDB document to API schema (removes _id)."""
    d = dict(doc)
    d.pop("_id", None)
    return d


@blp.route("")
class DevicesCollection(MethodView):
    """
    PUBLIC_INTERFACE
    GET /devices: Retrieve all devices.
    PUBLIC_INTERFACE
    POST /devices: Create a new device.
    """

    def get(self):
        """
        Retrieves all devices.
        Returns:
          200: JSON array of devices.
          500: Internal server error with error message.
        """
        logger.info("GET /devices requested")
        try:
            coll = _mongo_collection()
            devices = [_sanitize(d) for d in coll.find({}, {"_id": 0})]
            logger.info("GET /devices returned %d devices", len(devices))
            return devices, 200
        except Exception as e:
            logger.exception("Error fetching devices: %s", e)
            return {"error": "Internal server error."}, 500

    def post(self):
        """
        Creates a new device.
        Expects JSON body with fields: id (int), name, ip_address, device_type, location.
        Returns:
          201: Created device JSON.
          400: Bad request with validation errors.
          500: Internal server error.
        """
        logger.info("POST /devices requested")
        try:
            payload = request.get_json(force=True, silent=False)
        except Exception:
            logger.warning("POST /devices invalid JSON body")
            return {"error": "Invalid JSON body."}, 400

        errors = _validate_device_payload(payload, require_id=True)
        if errors:
            logger.info("POST /devices validation failed: %s", errors)
            return {"error": "Invalid input.", "errors": errors}, 400

        try:
            coll = _mongo_collection()
            # Ensure unique id
            existing = coll.find_one({"id": payload["id"]})
            if existing:
                logger.info("POST /devices conflict: id=%s already exists", payload["id"])
                return {"error": "Device with given id already exists."}, 400

            result = coll.insert_one({
                "id": payload["id"],
                "name": payload["name"].strip(),
                "ip_address": payload["ip_address"],
                "device_type": payload["device_type"],
                "location": payload["location"].strip(),
            })
            logger.info("POST /devices created device with _id=%s id=%s", str(result.inserted_id), payload["id"])
            created = coll.find_one({"id": payload["id"]}, {"_id": 0})
            return created, 201
        except PyMongoError as e:
            logger.exception("Database error on POST /devices: %s", e)
            return {"error": "Internal server error."}, 500
        except Exception as e:
            logger.exception("Unhandled error on POST /devices: %s", e)
            return {"error": "Internal server error."}, 500


@blp.route("/<int:device_id>")
class DeviceItem(MethodView):
    """
    PUBLIC_INTERFACE
    GET /devices/{id}: Retrieve device by ID.
    PUBLIC_INTERFACE
    PUT /devices/{id}: Update device by ID.
    PUBLIC_INTERFACE
    DELETE /devices/{id}: Delete device by ID.
    """

    def get(self, device_id: int):
        """
        Retrieves a device by id.
        Path params:
          id: integer unique device id
        Returns:
          200: Device JSON
          404: Not found
          500: Internal server error
        """
        logger.info("GET /devices/%s requested", device_id)
        try:
            coll = _mongo_collection()
            doc = coll.find_one({"id": device_id}, {"_id": 0})
            if not doc:
                logger.info("GET /devices/%s not found", device_id)
                return {"error": "Device not found."}, 404
            return doc, 200
        except Exception as e:
            logger.exception("Error fetching device %s: %s", device_id, e)
            return {"error": "Internal server error."}, 500

    def put(self, device_id: int):
        """
        Updates a device by id.
        Body must include name, ip_address, device_type, location.
        If body includes 'id', it must match the path id.
        Returns:
          200: Updated device
          400: Validation error
          404: Not found
          500: Internal server error
        """
        logger.info("PUT /devices/%s requested", device_id)
        try:
            payload = request.get_json(force=True, silent=False)
        except Exception:
            logger.warning("PUT /devices/%s invalid JSON body", device_id)
            return {"error": "Invalid JSON body."}, 400

        errors = _validate_device_payload(payload, require_id=False)
        if errors:
            logger.info("PUT /devices/%s validation failed: %s", device_id, errors)
            return {"error": "Invalid input.", "errors": errors}, 400

        if "id" in payload and payload["id"] != device_id:
            logger.info("PUT /devices/%s id mismatch: payload id=%s", device_id, payload["id"])
            return {"error": "Path id and payload id must match if 'id' is provided."}, 400

        try:
            coll = _mongo_collection()
            # Ensure device exists
            existing = coll.find_one({"id": device_id})
            if not existing:
                logger.info("PUT /devices/%s not found", device_id)
                return {"error": "Device not found."}, 404

            update_doc = {
                "name": payload["name"].strip(),
                "ip_address": payload["ip_address"],
                "device_type": payload["device_type"],
                "location": payload["location"].strip(),
            }
            coll.update_one({"id": device_id}, {"$set": update_doc})
            updated = coll.find_one({"id": device_id}, {"_id": 0})
            logger.info("PUT /devices/%s updated", device_id)
            return updated, 200
        except PyMongoError as e:
            logger.exception("Database error on PUT /devices/%s: %s", device_id, e)
            return {"error": "Internal server error."}, 500
        except Exception as e:
            logger.exception("Unhandled error on PUT /devices/%s: %s", device_id, e)
            return {"error": "Internal server error."}, 500

    def delete(self, device_id: int):
        """
        Deletes a device by id.
        Returns:
          204: No Content on success
          404: Not found
          500: Internal server error
        """
        logger.info("DELETE /devices/%s requested", device_id)
        try:
            coll = _mongo_collection()
            res = coll.delete_one({"id": device_id})
            if res.deleted_count == 0:
                logger.info("DELETE /devices/%s not found", device_id)
                return {"error": "Device not found."}, 404
            logger.info("DELETE /devices/%s deleted", device_id)
            return "", 204
        except PyMongoError as e:
            logger.exception("Database error on DELETE /devices/%s: %s", device_id, e)
            return {"error": "Internal server error."}, 500
        except Exception as e:
            logger.exception("Unhandled error on DELETE /devices/%s: %s", device_id, e)
            return {"error": "Internal server error."}, 500
