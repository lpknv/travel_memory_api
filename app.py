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
TRIPS_ID_URL = TRIPS_URL + '/<trip_id>'


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


@app.route(TRIPS_URL, methods=["GET"])
def get_trips():
    trips = [
        {
            "id":        trip.id,
            "name":      trip.name,
            "locations": [
                {
                    "id":       loc.id,
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
    """Create a new trip with locations"""
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


@app.route("/trips/<int:trip_id>", methods=["PATCH"])
def update_trip(trip_id):
    """Update a trip by id"""
    data = request.get_json() or {}

    trip = db.session.get(Trip, trip_id)
    if not trip:
        return jsonify({"message": "Trip not found"}), 404

    if "name" in data:
        name = data["name"]
        if not isinstance(name, str) or not name.strip():
            return jsonify({"message": "Name must be a non-empty string"}), 400
        trip.name = name.strip()

    db.session.commit()

    return jsonify({
        "message": "Trip updated",
        "trip":    {
            "id":   trip.id,
            "name": trip.name
        }
    }), 200


@app.route(TRIPS_URL + "/<int:trip_id>/locations", methods=["POST"])
def add_trip_location(trip_id):
    """Add a new location to a trip at the end"""
    data = request.get_json() or {}

    trip = db.session.get(Trip, trip_id)
    if not trip:
        return jsonify({"message": "Trip not found"}), 404

    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        return jsonify({"message": "Name must be a non-empty string"}), 400

    last_location = (
        TripLocation.query
        .filter_by(trip_id=trip_id)
        .order_by(TripLocation.position.desc())
        .first()
    )

    new_position = 0 if last_location is None else last_location.position + 1

    location = TripLocation(
        trip_id=trip_id,
        name=name.strip(),
        position=new_position
    )

    db.session.add(location)
    db.session.commit()

    return jsonify({
        "message":  "TripLocation created",
        "location": {
            "id":       location.id,
            "trip_id":  location.trip_id,
            "name":     location.name,
            "position": location.position
        }
    }), 201


@app.route("/trips/locations/<int:trip_location_id>", methods=["PATCH"])
def update_trip_location(trip_location_id):
    """Update a trip location by id"""
    data = request.get_json() or {}

    location = db.session.get(TripLocation, trip_location_id)
    if not location:
        return jsonify({"message": "TripLocation not found"}), 404

    if "name" in data:
        name = data["name"]
        if not isinstance(name, str) or not name.strip():
            return jsonify({"message": "Name must be a non-empty string"}), 400
        location.name = name.strip()

    db.session.commit()

    return jsonify({
        "message":  "TripLocation updated",
        "location": {
            "id":       location.id,
            "trip_id":  location.trip_id,
            "name":     location.name,
            "position": location.position
        }
    }), 200


@app.route(TRIPS_URL + "/<int:trip_id>/locations/reorder", methods=["PATCH"])
def reorder_trip_locations(trip_id):
    "Reorder trip location positions"
    data = request.get_json() or {}
    location_ids = data.get("location_ids")

    if not isinstance(location_ids, list) or not location_ids:
        return jsonify({"message": "location_ids must be a non-empty list"}), 400

    if not all(isinstance(loc_id, int) for loc_id in location_ids):
        return jsonify({"message": "All location_ids must be integers"}), 400

    trip = db.session.get(Trip, trip_id)
    if not trip:
        return jsonify({"message": "Trip not found"}), 404

    locations = (
        TripLocation.query
        .filter_by(trip_id=trip_id)
        .order_by(TripLocation.position.asc())
        .all()
    )

    if not locations:
        return jsonify({"message": "No locations found for this trip"}), 404

    existing_ids = [loc.id for loc in locations]
    existing_id_set = set(existing_ids)

    if len(location_ids) != len(existing_ids):
        return jsonify({
            "message": "location_ids must contain all trip locations exactly once"
        }), 400

    if len(set(location_ids)) != len(location_ids):
        return jsonify({
            "message": "location_ids must not contain duplicates"
        }), 400

    if set(location_ids) != existing_id_set:
        return jsonify({
            "message": "location_ids must match exactly the trip's locations"
        }), 400

    location_map = {loc.id: loc for loc in locations}

    for index, loc_id in enumerate(location_ids):
        location_map[loc_id].position = index

    db.session.commit()

    updated_locations = (
        TripLocation.query
        .filter_by(trip_id=trip_id)
        .order_by(TripLocation.position.asc())
        .all()
    )

    return jsonify({
        "message":   "TripLocations reordered",
        "locations": [
            {
                "id":       loc.id,
                "trip_id":  loc.trip_id,
                "name":     loc.name,
                "position": loc.position
            }
            for loc in updated_locations
        ]
    }), 200


@app.route(TRIPS_ID_URL, methods=["GET"])
@jwt_required()
def get_trip(trip_id):
    """Get a single trip with locations"""

    trip = db.session.get(Trip, id=trip_id)
    if not trip:
        return jsonify({"message": "Trip not found"}), 404

    locations = (
        TripLocation.query
        .filter_by(trip_id=trip.id)
        .order_by(TripLocation.position.asc())
        .all()
    )

    return jsonify({
        "trip": {
            "id":        trip.id,
            "name":      trip.name,
            "locations": [
                {
                    "id":       loc.id,
                    "name":     loc.name,
                    "position": loc.position
                }
                for loc in locations
            ]
        }
    }), 200


@app.route(TRIPS_ID_URL, methods=["DELETE"])
@jwt_required()
def delete_trip(trip_id):
    """Delete a single trip"""
    pass


@app.route(BASE_URL + "/timeline", methods=["GET"])
@jwt_required()
def timeline():
    """Returns the timeline of all trips"""
    pass


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(port=5001, debug=True)