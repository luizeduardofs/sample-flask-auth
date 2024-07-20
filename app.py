from flask import Flask, request, jsonify
from database import db
from models.user import User
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'xd235xcd4xd64863468qw'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message": "Autenticação realizada com sucesso"})

    return jsonify({"message": "Credenciais invpalidas"}), 400

@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso"})

@app.route("/user", methods=["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        user = User(username=username, password=hashed_password, role='user')
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Usuário cadastrado com sucesso"})
    
    return jsonify({"message": "Dados inválidos"}), 400

@app.route("/user/<int:id>", methods=["GET"])
@login_required
def read_user(id):
    user = User.query.get(id)

    if user:
        return {"username": user.username}

    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route("/user/<int:id>", methods=["PUT"])
@login_required
def update_user(id):
    data = request.json
    user = User.query.get(id)

    if id != current_user.id and current_user.role == "user":
        return jsonify({"message": "Operação não autorizada"}), 404

    if user and data.get("password"):
        user.password = data.get("password")
        db.session.commit()
        return jsonify({"message": f"Usuário {id} atualizado com sucesso"}), 202

    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route("/user/<int:id>", methods=["DELETE"])
@login_required
def delete_user(id):
    user = User.query.get(id)

    if current_user.role != "admin":
        return jsonify({"message": "Deleção não permitida"}), 404

    if user and id != current_user.id:
        db.session.remove(user)
        db.session.commit()
        return jsonify({"message": f"Usuário {id} deletado com sucesso"})

    return jsonify({"message": "Operação não permitida"}), 403


if __name__ == "__main__":
    app.run(debug=True)
