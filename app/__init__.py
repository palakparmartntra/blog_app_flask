from flask import Flask
from flask_migrate import Migrate 
from datetime import datetime
from flask_restplus import Api ,Resource
from flask import request, jsonify, session
from flask_bcrypt import Bcrypt
import jwt
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:postgres@localhost:5432/blog"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['SECRET_KEY'] = "6c1a13276235441e9768203dc37305c3"
db = SQLAlchemy(app)
migrate = Migrate(app, db)

bcrypt = Bcrypt(app)
api = Api(app)

ma = Marshmallow(app)

from app import views