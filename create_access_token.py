from app import app

with app.test_client() as client:
    response = client.post(
        "/api/auth/login",
        json={
            "email": "test2@text.com",
            "password": "test2",
        },
    )

    print(response.get_json()["access_token"])
