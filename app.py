from flask import Blueprint, Flask, g, jsonify, redirect, request, url_for
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt, get_jwt_identity, jwt_required

from models import Trip, TripLocation, User, db

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:@localhost/travel_memory_api_db"
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!

db.init_app(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

BASE_URL = '/api'
TRIPS_URL = BASE_URL + '/trips'
TRIPS_CREATE_URL = TRIPS_URL + '/create'
TRIPS_ID_URL = BASE_URL + TRIPS_URL + '/<trip_id>'


@app.route('/')
def index():
    users = User.query.all()

    return jsonify(
        [user.to_dict() for user in users]
    )


# -------------------
# AUTH
# -------------------
@app.route(BASE_URL + "/auth/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data:
        return jsonify({"message": "No data provided"}), 400

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    user = db.session.execute(
        db.select(User).filter_by(email=email)
    ).scalar_one_or_none()

    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({"message": "Invalid credentials"}), 401

    access_token = create_access_token(identity=str(user.id))

    return jsonify({
        "access_token": access_token
    }), 200


@app.route(BASE_URL + "/auth/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data:
        return jsonify({"message": "No data provided"}), 400

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    user = User(
        email=email,
        password_hash=bcrypt.generate_password_hash(password).decode("utf-8"),
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Success!"}), 201


# -------------------
# PROFILE
# -------------------
@app.route(BASE_URL + "/me", methods=["GET"])
@jwt_required()
def get_me():
    user_id = int(get_jwt_identity())
    user = db.session.get(User, user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify({
        "id":    user.id,
        "email": user.email
    })


# -------------------
# TRIPS
# -------------------
@app.route(TRIPS_URL, methods=["GET"])
def get_trips():
    trips = [
        {
            "name":      trip.name,
            "locations": [
                {
                    "name":     loc.name,
                    "position": loc.position
                }
                for loc in trip.locations
            ]
        }
        for trip in Trip.query.all()
    ]

    return jsonify(trips), 200


@app.route(TRIPS_CREATE_URL, methods=["POST"])
def create_trip():
    data = request.get_json()

    name = data.get("name")
    locations = data.get("locations")

    if not name or not locations:
        return jsonify({"message": "Name and locations are required"}), 400

    if len(locations) < 2:
        return jsonify({"message": "At least 2 locations required"}), 400

    trip = Trip(name=name)
    db.session.add(trip)
    db.session.flush()

    for index, loc_name in enumerate(locations):
        trip_location = TripLocation(
            trip_id=trip.id,
            name=loc_name,
            position=index
        )
        db.session.add(trip_location)

    db.session.commit()

    return jsonify({"message": "Trip created"}), 201


@app.route(TRIPS_ID_URL, methods=["GET"])
@jwt_required()
def get_trip(trip_id):
    pass


@app.route(TRIPS_ID_URL, methods=["DELETE"])
@jwt_required()
def delete_trip(trip_id):
    pass


# -------------------
# TIMELINE
# -------------------
@app.route("/timeline", methods=["GET"])
@jwt_required()
def timeline():
    pass


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(port=5001, debug=True)