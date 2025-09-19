
from flask import Flask, render_template, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

#Configuração inicial
app = Flask(_name_)

app.config['SECRET_KEY'] = os.urandom(20)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#------------------------------------------------------------------------------
# MODELS
#------------------------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(20), nullable=False)
    task = db.relationship('Task', backref='user', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150))
    Status = db.Column(db.String(20), default='Pendente')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

#------------------------------------------------------------------------------
# LOGIN MANAGER
#------------------------------------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#-------------------------------------------------------------------------------
# ROTAS
#-------------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template('index.html')

#cadastro de usuário -- CREATE
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        #verificar se já existe o usuário
        user = User.query.filter_by(email=email).first()
        if user:
            flash('E-mail já cadastrado!', 'warning')
            return redirect(url_for('register'))

        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Cadastro realizdo com sucesso! Faça login', 'sucess')
        return redirect(url_for('login'))
     
    return render_template('register.html')

#login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('tasks'))
        else:
            flash('E-mail ou senha incorretos.', 'danger')

    return render_template('login.html')

#logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

#listar tarefas --- READ
@app.route('/tasks')
@login_required
def tasks():
    user_tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template('tasks.html', tasks=user_tasks)

#Adicionar Tarefa --- CREATE
@app.route('/add_tasks', methods=['POST', 'GET'])
@login_required
def add_tasks():
    if request.method == 'POST':
        title = request.form['title']
        new_task = Task(title=title, user_id=current_user.id)

        db.session.add(new_task)
        db.session.commit()
        flash('Tarefa adicionada com sucesso!', 'success')
        return redirect(url_for('tasks'))

        return render_template('add_tasks.html')

#Atualizar status da tarefa -- UPDATE
@app.route('/update_task/<int:id>')
@login_required
def update_task(id):
    task = Task.query.get_or_404(id)

    if task.user_id != current_user.id:
        flash('Você não tem permissão para usar isso!', 'danger')
        return redirect(url_for('tasks'))

    task.status = "Concluida" if task.status == "Pendente" else "Pendente"
    db.session.commit()
    return redirect(url_for('tasks'))

#Deletar tarefa -- DELETE
@app.route('/delete_task/<int:id>')
@login_required
def delete_task(id):
    task = Task.query.get_or_404(id)

    if task.user_id != current_user.id:
        flash('Você não tem permissão para usar isso!', 'danger')
        return redirect(url_for('tasks'))

    db.session.delete(task)
    deb.session.commit()
    flash('Tarefa excluida!', 'info')
    return redirect(url_for('tasks'))


#-------------------------------------------------------------------------------
# CRIAR O BANCO NA PRIMEIRA EXECUÇÃO
#-------------------------------------------------------------------------------
if _name_ == "_main_":
    if not os.path.exists('database.db'):
        with app.app_context():
            db.create_all()
            
    app.run(debug=True)
