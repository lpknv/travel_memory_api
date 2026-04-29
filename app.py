from datetime import timedelta
import os
from dotenv import load_dotenv

from flask import Flask, request
from flask_restx import Api, Resource, fields
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)

from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_cors import CORS

from models import Trip, TripLocation, Photo, User, db
from helpers import paginate_query


load_dotenv()

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
app.config["SWAGGER_UI_DOC_EXPANSION"] = "list"
app.config["SWAGGER_UI_CONFIG"] = {"persistAuthorization": True}

app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(
    hours=int(os.getenv("JWT_EXPIRES_HOURS", 8))
)

CORS(app, origins=["http://tm-api.test"])
migrate = Migrate(app, db)
db.init_app(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)


api = Api(
    app,
    doc="/swagger/docs/",
    title="Travel Memory API",
    version="1.0",
    description="API",
    authorizations={
        "Bearer": {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "Bearer <token>",
        }
    },
    security="Bearer",
    ordered=True,
)

auth_ns = api.namespace("Auth", path="/api/auth")
profile_ns = api.namespace("Profile", path="/api/me")
users_ns = api.namespace("Users", path="/api/users")
trips_ns = api.namespace("Trips", path="/api/trips")
trip_locations_ns = api.namespace("TripLocations", path="/api/trip-locations")


login_model = api.model(
    "Login",
    {
        "email": fields.String(required=True),
        "password": fields.String(required=True),
    },
)

register_model = api.model(
    "Register",
    {
        "email": fields.String(required=True),
        "password": fields.String(required=True),
    },
)

token_model = api.model("Token", {"access_token": fields.String})

message_model = api.model("Message", {"message": fields.String})

user_model = api.model("User", {"email": fields.String})

photo_model = api.model(
    "Photo",
    {
        "id": fields.Integer,
        "name": fields.String,
        "path": fields.String,
        "created_at": fields.DateTime,
    },
)

location_model = api.model(
    "Location",
    {
        "id": fields.Integer,
        "name": fields.String,
        "trip_id": fields.Integer,
        "created_at": fields.DateTime,
        "photos": fields.List(fields.Nested(photo_model)),
    },
)

trip_model = api.model(
    "Trip",
    {
        "id": fields.Integer,
        "name": fields.String,
        "created_at": fields.DateTime,
        "locations": fields.List(fields.Nested(location_model)),
    },
)

create_trip_model = api.model(
    "CreateTrip",
    {
        "name": fields.String,
        "locations": fields.List(fields.Raw),
    },
)

update_trip_model = api.model("UpdateTrip", {"name": fields.String})


@auth_ns.route("/login")
class LoginResource(Resource):
    @auth_ns.expect(login_model)
    @auth_ns.marshal_with(token_model)
    def post(self):
        data = request.get_json() or {}

        user = db.session.execute(
            db.select(User).filter_by(email=data.get("email"))
        ).scalar_one_or_none()

        if not user or not bcrypt.check_password_hash(
            user.password_hash, data.get("password", "")
        ):
            api.abort(401, "Invalid credentials")

        return {"access_token": create_access_token(identity=str(user.id))}


@auth_ns.route("/register")
class RegisterResource(Resource):
    @auth_ns.expect(register_model)
    def post(self):
        data = request.get_json() or {}

        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            api.abort(400, "Invalid input")

        if db.session.execute(
            db.select(User).filter_by(email=email)
        ).scalar_one_or_none():
            api.abort(409, "User exists")

        user = User(
            email=email,
            password_hash=bcrypt.generate_password_hash(password).decode(),
        )

        db.session.add(user)
        db.session.commit()

        return {"message": "Success"}, 201


@profile_ns.route("/")
class MeResource(Resource):
    method_decorators = [jwt_required()]

    @profile_ns.marshal_with(user_model)
    def get(self):
        user = db.session.get(User, int(get_jwt_identity()))
        if not user:
            api.abort(404)
        return user


@users_ns.route("/")
class UsersResource(Resource):
    def get(self):
        return User.query.all()


@trips_ns.route("/")
class TripsResource(Resource):
    method_decorators = [jwt_required()]

    def get(self):
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 10, type=int)

        return paginate_query(Trip.query, trip_model, page, per_page)

    @trips_ns.expect(create_trip_model)
    def post(self):
        data = request.get_json() or {}

        trip = Trip(name=data.get("name"))
        db.session.add(trip)
        db.session.flush()

        for loc in data.get("locations", []):
            tl = TripLocation(trip_id=trip.id, name=loc.get("name"))
            db.session.add(tl)
            db.session.flush()

            for p in loc.get("photos", []):
                db.session.add(
                    Photo(
                        trip_location_id=tl.id,
                        name=p.get("name"),
                        path=p.get("path"),
                    )
                )

        db.session.commit()
        return {"message": "Trip created"}, 201


@trips_ns.route("/<int:trip_id>")
class TripResource(Resource):
    method_decorators = [jwt_required()]

    @trips_ns.marshal_with(trip_model)
    def get(self, trip_id):
        trip = db.session.get(Trip, trip_id)
        if not trip:
            api.abort(404)
        return trip

    @trips_ns.expect(update_trip_model)
    def patch(self, trip_id):
        trip = db.session.get(Trip, trip_id)
        if not trip:
            api.abort(404)

        trip.name = request.json.get("name", trip.name)
        db.session.commit()

        return {"message": "updated"}


@trip_locations_ns.route("/")
class TripLocationsResource(Resource):
    method_decorators = [jwt_required()]

    def get(self):
        return TripLocation.query.all()


PORT = int(os.getenv("PORT", 5000))
HOST = os.getenv("HOST", "0.0.0.0")
FLASK_ENV = os.getenv("FLASK_ENV", "development")
DEBUG = FLASK_ENV == "development"

PHOTOS_DIR = os.path.join(os.getcwd(), "photos")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    if DEBUG:
        app.run(host=HOST, port=PORT, debug=True)
    else:
        from waitress import serve

        serve(app, host=HOST, port=PORT)
