from faker import Faker
from app import app, db
from models import Trip, TripLocation, Photo
import random

fake = Faker()

with app.app_context():
    trips = Trip.query.all()

    for trip in trips:
        num_locations = random.randint(3, 8)

        for _ in range(num_locations):
            location = TripLocation(
                name=fake.city(),
                trip_id=trip.id,
                photos=[
                    Photo(
                        path="https://images.pexels.com/photos/33693338/pexels-photo-33693338.jpeg",
                        name=fake.city(),
                    )
                    for _ in range(random.randint(1, 3))
                ],
            )

            db.session.add(location)

    db.session.commit()

print("Locations created.")
