from flask import Flask
from flask_cors import CORS
from flask_smorest import Api
from .routes.health import blp as health_blp
from .routes.devices import blp as devices_blp

# Initialize Flask app
app = Flask(__name__)
app.url_map.strict_slashes = False
CORS(app, resources={r"/*": {"origins": "*"}})

# OpenAPI / Swagger configuration
app.config["API_TITLE"] = "NetWeb Device Management API"
app.config["API_VERSION"] = "1.0.0"
app.config["OPENAPI_VERSION"] = "3.0.3"
app.config['OPENAPI_URL_PREFIX'] = '/docs'
app.config["OPENAPI_SWAGGER_UI_PATH"] = ""
app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"
app.config["OPENAPI_REDOC_PATH"] = None

# Tag descriptions for documentation
openapi_tags = [
    {"name": "Healt Check", "description": "Health check route"},
    {"name": "Devices", "description": "Operations related to device management"},
]

api = Api(app)
api.spec.components.security_scheme("none", {"type": "http", "scheme": "none"})  # explicit no auth
for t in openapi_tags:
    api.spec.tag(t)

# Register blueprints
api.register_blueprint(health_blp)
api.register_blueprint(devices_blp)
