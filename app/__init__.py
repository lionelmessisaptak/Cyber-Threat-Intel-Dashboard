from flask import Flask
from flask_pymongo import PyMongo
from dotenv import load_dotenv
import os

mongo = PyMongo()  # Move mongo here globally, to be imported in routes

def create_app():
    load_dotenv()

    app = Flask(__name__)
    app.config.from_pyfile('../config.py')
    app.secret_key = os.getenv("SECRET_KEY", "default-secret")

    # MongoDB setup
    app.config['MONGO_URI'] = "mongodb://localhost:27017/cti_dashboard"
    mongo.init_app(app)

    # Register routes blueprint **AFTER** initializing mongo
    from app.routes import routes_blueprint
    app.register_blueprint(routes_blueprint)

    return app
