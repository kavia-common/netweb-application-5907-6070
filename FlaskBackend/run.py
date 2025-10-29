from app import app

def main():
    """
    PUBLIC_INTERFACE
    Entrypoint for running the Flask application.
    Starts the development server. For production, use a WSGI server (e.g., gunicorn).
    """
    app.run(host="0.0.0.0", port=5000)

if __name__ == "__main__":
    main()
