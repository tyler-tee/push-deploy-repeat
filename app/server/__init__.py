from flask import Flask
from .update_server import update_server


def create_app():
    app = Flask(__name__)
    app.register_blueprint(update_server)
    return app
