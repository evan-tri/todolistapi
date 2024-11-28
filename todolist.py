from flask import Flask, request, jsonify
from bcrypt import hashpw, gensalt
import jwt
import datetime

app = Flask(__name__)

SECRET_KEY = "your_secret_key"

users = []
tasks = []

def generate_token(user_id):
    payload ={
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return token

def decode_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return {'error': 'Token has expired'}
    except jwt.InvalidTokenError:
        return {'error': 'Invalid token'}

@app.route('/register', methods=['POST'])
def register_user():
    data = request.json

    if not data or "name" not in data or "password" not in data or "email" not in data:
        return jsonify({"error": "Name, email, and password are required"}), 400
    
    if any(user['name'] == data['name'] for user in users):
        return jsonify({"error": "Name already exists"}), 400
    
    hashed_password = hashpw(data['password'].encode('utf-8'), gensalt())
    
    user = {
        "id": len(users) + 1,
        "name": data['name'],
        "email": data['email'],
        "password": hashed_password.decode('utf-8')
    }

    users.append(user)

    token = generate_token(user['id'])

    return jsonify({
        "message": "User registered successfully", 
        "user": {"id": user["id"], "username": user['name']}, 
        "token": token
    }), 201

@app.route('/users', methods=['GET'])
def list_users():
    return jsonify(users), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.json

    if not data or "name" not in data or "password" not in data:
        return jsonify({'error': 'Username and password are required'}), 400
    
    user = next((user for user in users if user['name'] == data['name']), None)
    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401
    
    token = generate_token(user['id'])

    return jsonify({
        'message': 'Login successful',
        'token': token
    }), 200

@app.route('/todos', methods=['POST'])
def new_task():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    token = auth_header.split(" ")[1]
    decoded = decode_token(token)
    if "error" in decoded:
        return jsonify(decoded), 401
    
    user_id = decoded['user_id']

    data = request.json
    if not data or "title" not in data:
        return jsonify({'error': 'Task title is required'}), 400
    
    task = {
        "task_id": len(tasks) + 1,
        "user_id": user_id,
        "title": data['title'],
        'description': data.get('description', "")
    }

    tasks.append(task)

    return jsonify({
        'message': 'Task created successfully',
        'task': task
    }), 201

@app.route('/todos/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    token = auth_header.split(" ")[1]
    decoded = decode_token(token)
    if "error" in decoded:
        return jsonify(decoded), 401
    
    user_id = decoded['user_id']

    task = next((task for task in tasks if task['task_id'] == task_id), None)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    
    if task['user_id'] != user_id:
        return jsonify({'error': 'Forbidden'}), 403
    
    data = request.json
    if not data:
        return jsonify({'error': 'No data provided for update'}), 400
    
    task['title'] = data.get('title', task['title'])
    task['description'] = data.get('description', task['description'])
    
    return jsonify({'message': "Task updated successfully", "task": task}), 200

@app.route('/todos/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    token = auth_header.split(" ")[1]
    decoded = decode_token(token)
    if "error" in decoded:
        return jsonify(decoded), 401
    
    user_id = decoded['user_id']

    task = next((task for task in tasks if task['task_id'] == task_id), None)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    
    if task['user_id'] != user_id:
        return jsonify({'error': 'Forbidden'}), 403
    
    data = request.json
    del tasks['title']
    del tasks['description']
    del tasks['task_id']
    del tasks['user_id']

    return jsonify({'message': 'Task deleted successfully', 'task': task}), 204

@app.route('/todos', methods=['GET'])
def list_tasks():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    token = auth_header.split(" ")[1]
    decoded = decode_token(token)
    if "error" in decoded:
        return jsonify(decoded), 401
    
    user_id = decoded['user_id']

    user_tasks = [task for task in tasks if task.get("user_id") == user_id]

    return jsonify({'tasks': user_tasks}), 200

if __name__ == "__main__":
    app.run(debug=True)