from faker import Faker
from app import app, db
from models import Trip, TripLocation
from datetime import datetime, timedelta
import random

fake = Faker()

with app.app_context():
    trips = Trip.query.all()

    for trip in trips:
        num_locations = random.randint(3, 8)

        for i in range(num_locations):
            location = TripLocation(
                name=fake.city(),
                position=i,  # 👈 wichtig für Timeline!
                trip_id=trip.id
            )

            db.session.add(location)

    db.session.commit()

print("Locations created.")