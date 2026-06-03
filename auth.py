USERS = {
    "admin": "admin123",
    "bob": "password123"
}


def authenticate(username, password):
    return USERS.get(username) == password