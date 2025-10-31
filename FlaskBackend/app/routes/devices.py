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


def _validate_device_payload(payload: Dict[str, Any]) -> Optional[Dict[str, List[str]]]:
    """
    Validates device payload for create/update.
    Ensures 'name', 'ip_address', 'device_type', and 'location' are valid.
    Returns None if valid, otherwise a dict of field->list(errors).
    """
    errors: Dict[str, List[str]] = {}

    # Disallow id entirely now
    if "id" in payload:
        errors.setdefault("id", []).append("Field 'id' is not allowed.")

    # name
    name = payload.get("name")
    if name is None or not isinstance(name, str) or not name.strip():
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
    # Ensure unique index on 'name'
    try:
        coll.create_index([("name", ASCENDING)], unique=True, background=True)
    except Exception as e:
        logger.warning("Could not ensure index on 'name': %s", e)
    return coll


def _sanitize(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Converts MongoDB document to API schema (removes internal fields like _id and legacy id)."""
    d = dict(doc)
    d.pop("_id", None)
    d.pop("id", None)
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
            return {"error": e}, 500

    def post(self):
        """
        Creates a new device.
        Expects JSON body with fields: name, ip_address, device_type, location.
        Returns:
          201: Created device JSON (without internal identifiers).
          400: Bad request with validation errors.
          500: Internal server error.
        """
        logger.info("POST /devices requested")
        try:
            payload = request.get_json(force=True, silent=False)
        except Exception:
            logger.warning("POST /devices invalid JSON body")
            return {"error": "Invalid JSON body."}, 400

        errors = _validate_device_payload(payload)
        if errors:
            logger.info("POST /devices validation failed: %s", errors)
            return {"error": "Invalid input.", "errors": errors}, 400

        try:
            coll = _mongo_collection()
            # Application-level uniqueness check on 'name'
            existing = coll.find_one({"name": payload["name"].strip()})
            if existing:
                logger.info("POST /devices conflict: name=%s already exists", payload["name"])
                return {"error": "Device with given name already exists."}, 400

            coll.insert_one({
                "name": payload["name"].strip(),
                "ip_address": payload["ip_address"],
                "device_type": payload["device_type"],
                "location": payload["location"].strip(),
            })
            created = coll.find_one({"name": payload["name"].strip()})
            if not created:
                logger.error("POST /devices: created document not found by name lookup.")
                return {"error": "Internal server error."}, 500
            return _sanitize(created), 201
        except PyMongoError as e:
            logger.exception("Database error on POST /devices: %s", e)
            return {"error": "Internal server error."}, 500
        except Exception as e:
            logger.exception("Unhandled error on POST /devices: %s", e)
            return {"error": "Internal server error."}, 500


@blp.route("/<string:name>")
class DeviceItem(MethodView):
    """
    PUBLIC_INTERFACE
    GET /devices/{name}: Retrieve device by name.
    PUBLIC_INTERFACE
    PUT /devices/{name}: Update device by name.
    PUBLIC_INTERFACE
    DELETE /devices/{name}: Delete device by name.
    """

    def get(self, name: str):
        """
        Retrieves a device by name.
        Path params:
          name: unique device name
        Returns:
          200: Device JSON
          404: Not found
          500: Internal server error
        """
        logger.info("GET /devices/%s requested", name)
        try:
            coll = _mongo_collection()
            doc = coll.find_one({"name": name})
            if not doc:
                logger.info("GET /devices/%s not found", name)
                return {"error": "Device not found."}, 404
            return _sanitize(doc), 200
        except Exception as e:
            logger.exception("Error fetching device %s: %s", name, e)
            return {"error": "Internal server error."}, 500

    def put(self, name: str):
        """
        Updates a device by name.
        Body must include name, ip_address, device_type, location.
        Returns:
          200: Updated device
          400: Validation error
          404: Not found
          500: Internal server error
        """
        logger.info("PUT /devices/%s requested", name)
        try:
            payload = request.get_json(force=True, silent=False)
        except Exception:
            logger.warning("PUT /devices/%s invalid JSON body", name)
            return {"error": "Invalid JSON body."}, 400

        errors = _validate_device_payload(payload)
        if errors:
            logger.info("PUT /devices/%s validation failed: %s", name, errors)
            return {"error": "Invalid input.", "errors": errors}, 400

        try:
            coll = _mongo_collection()
            # Ensure device exists with current name
            existing = coll.find_one({"name": name})
            if not existing:
                logger.info("PUT /devices/%s not found", name)
                return {"error": "Device not found."}, 404

            new_name = payload["name"].strip()
            # If renaming, ensure new name is unique
            if new_name != name:
                conflict = coll.find_one({"name": new_name})
                if conflict:
                    logger.info("PUT /devices/%s conflict: new name '%s' already exists", name, new_name)
                    return {"error": "Device with given name already exists."}, 400

            update_doc = {
                "name": new_name,
                "ip_address": payload["ip_address"],
                "device_type": payload["device_type"],
                "location": payload["location"].strip(),
            }
            coll.update_one({"name": name}, {"$set": update_doc})
            updated = coll.find_one({"name": new_name})
            logger.info("PUT /devices/%s updated", name)
            return _sanitize(updated), 200
        except PyMongoError as e:
            logger.exception("Database error on PUT /devices/%s: %s", name, e)
            return {"error": "Internal server error."}, 500
        except Exception as e:
            logger.exception("Unhandled error on PUT /devices/%s: %s", name, e)
            return {"error": "Internal server error."}, 500

    def delete(self, name: str):
        """
        Deletes a device by name.
        Returns:
          204: No Content on success
          404: Not found
          500: Internal server error
        """
        logger.info("DELETE /devices/%s requested", name)
        try:
            coll = _mongo_collection()
            res = coll.delete_one({"name": name})
            if res.deleted_count == 0:
                logger.info("DELETE /devices/%s not found", name)
                return {"error": "Device not found."}, 404
            logger.info("DELETE /devices/%s deleted", name)
            return "", 204
        except PyMongoError as e:
            logger.exception("Database error on DELETE /devices/%s: %s", name, e)
            return {"error": "Internal server error."}, 500
        except Exception as e:
            logger.exception("Unhandled error on DELETE /devices/%s: %s", name, e)
            return {"error": "Internal server error."}, 500
