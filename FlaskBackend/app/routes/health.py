from flask_smorest import Blueprint
from flask.views import MethodView

# PUBLIC_INTERFACE
# Health check blueprint
blp = Blueprint("Healt Check", "health check", url_prefix="/", description="Health check route")


@blp.route("/")
class HealthCheck(MethodView):
    """Health check endpoint."""
    def get(self):
        """Returns health status of the service."""
        return {"message": "Healthy"}
