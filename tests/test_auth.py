from auth import authenticate

print(authenticate("admin", "admin123"))
print(authenticate("admin", "wrongpassword"))