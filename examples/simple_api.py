from fastapi import FastAPI, HTTPException, Query, Path, Body, Header
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from enum import Enum

app = FastAPI(
    title="Simple User API",
    version="1.0.0",
    description="A simple API for managing users"
)

class Role(str, Enum):
    admin = "admin"
    user = "user"
    guest = "guest"

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=20, pattern="^[a-zA-Z0-9_]+$")
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    age: Optional[int] = Field(default=None, ge=18, le=150)
    role: Role = Role.user

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    age: Optional[int] = Field(default=None, ge=18, le=150)

class User(BaseModel):
    id: int
    username: str
    email: EmailStr
    age: Optional[int] = None
    role: Role

users = []
current_id = 1

@app.get("/users", response_model=List[User])
def list_users(
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    return users[offset: offset + limit]

@app.post("/users", status_code=201)
def create_user(user: UserCreate):
    global current_id

    for u in users:
        if u["username"] == user.username:
            raise HTTPException(status_code=409, detail="User already exists")

    new_user = {
        "id": current_id,
        "username": user.username,
        "email": user.email,
        "age": user.age,
        "role": user.role,
    }

    users.append(new_user)
    current_id += 1

    return {
        "id": new_user["id"],
        "username": new_user["username"],
        "message": "User created successfully"
    }

@app.get("/users/{userId}")
def get_user(
    userId: int = Path(..., ge=1),
    includeDetails: bool = Query(False)
):
    for user in users:
        if user["id"] == userId:
            return user
    raise HTTPException(status_code=404, detail="User not found")

@app.put("/users/{userId}")
def update_user(
    userId: int,
    updates: UserUpdate
):
    for user in users:
        if user["id"] == userId:
            if updates.email is not None:
                user["email"] = updates.email
            if updates.age is not None:
                user["age"] = updates.age
            return {"message": "User updated"}
    raise HTTPException(status_code=404, detail="User not found")

@app.delete("/users/{userId}", status_code=204)
def delete_user(userId: int):
    global users
    for user in users:
        if user["id"] == userId:
            users = [u for u in users if u["id"] != userId]
            return
    raise HTTPException(status_code=404, detail="User not found")
