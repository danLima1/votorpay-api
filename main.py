from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS  # Importa Flask-CORS
import jwt
import datetime
from functools import wraps
import requests
import random
import string

app = Flask(__name__)
CORS(app)  # Habilita CORS para todas as rotas e origens
# -----------------------------------------------------------------------------
# Configurações
# -----------------------------------------------------------------------------
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:POqEhF0Uz8N1IPQk@maliciously-upward-kelpie.data-1.use1.tembo.io:5432/postgres'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'fa0b66aedea910162f3bdb38c72817923e3807a53090d4683d50e00337ea86c4'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# -----------------------------------------------------------------------------
# Modelos
# -----------------------------------------------------------------------------
class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nome = db.Column(db.String(100), nullable=False)
    cpf = db.Column(db.String(11), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    numero_celular = db.Column(db.String(20), nullable=False)
    senha = db.Column(db.String(128), nullable=False)
    codigo_indicacao = db.Column(db.String(10), unique=True)
    indicado_por = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=True)

    consultas_hoje = db.Column(db.Integer, default=0)
    data_ultima_consulta = db.Column(db.Date, default=datetime.date.today())
    consultas_totais = db.Column(db.Integer, default=0)
    saldo = db.Column(db.Float, default=0.0)

# -----------------------------------------------------------------------------
# Funções auxiliares
# -----------------------------------------------------------------------------
def token_requerido(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            parts = auth_header.split()
            if len(parts) == 2 and parts[0].lower() == 'bearer':
                token = parts[1]

        if not token:
            return jsonify({'message': 'Token JWT não fornecido.'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Usuario.query.get(data['id'])
            if not current_user:
                return jsonify({'message': 'Usuário não encontrado.'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expirado.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido.'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

def gerar_token(usuario):
    payload = {
        'id': usuario.id,
        'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=24)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token

def verificar_limite_diario(usuario):
    hoje = datetime.date.today()
    if usuario.data_ultima_consulta != hoje:
        usuario.data_ultima_consulta = hoje
        usuario.consultas_hoje = 0

    if usuario.consultas_hoje < 10:
        return True
    else:
        return False

# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------
@app.route('/cadastro', methods=['POST'])
def cadastro():
    data = request.json
    nome = data.get('nome')
    cpf = data.get('cpf')
    email = data.get('email')
    numero_celular = data.get('numero_celular')
    senha = data.get('senha')
    codigo_indicacao_usado = data.get('codigo_indicacao')  # Opcional

    if not all([nome, cpf, email, numero_celular, senha]):
        return jsonify({'message': 'Dados incompletos no cadastro.'}), 400

    if Usuario.query.filter_by(cpf=cpf).first():
        return jsonify({'message': 'CPF já cadastrado.'}), 400
    if Usuario.query.filter_by(email=email).first():
        return jsonify({'message': 'E-mail já cadastrado.'}), 400

    # Verificar código de indicação se fornecido
    indicador = None
    if codigo_indicacao_usado:
        indicador = Usuario.query.filter_by(codigo_indicacao=codigo_indicacao_usado).first()
        if not indicador:
            return jsonify({'message': 'Código de indicação inválido.'}), 400

    senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

    # Gerar código de indicação único
    while True:
        novo_codigo = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        if not Usuario.query.filter_by(codigo_indicacao=novo_codigo).first():
            break

    novo_usuario = Usuario(
        nome=nome,
        cpf=cpf,
        email=email,
        numero_celular=numero_celular,
        senha=senha_hash,
        codigo_indicacao=novo_codigo,
        indicado_por=indicador.id if indicador else None
    )

    db.session.add(novo_usuario)
    
    # Adicionar R$ 5,00 ao saldo do indicador
    if indicador:
        indicador.saldo += 5.0
    
    db.session.commit()

    return jsonify({'message': 'Usuário cadastrado com sucesso!'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    cpf = data.get('cpf')
    senha = data.get('senha')

    if not all([cpf, senha]):
        return jsonify({'message': 'CPF e senha são necessários.'}), 400

    usuario = Usuario.query.filter_by(cpf=cpf).first()
    if not usuario:
        return jsonify({'message': 'Usuário não encontrado.'}), 404

    if bcrypt.check_password_hash(usuario.senha, senha):
        token = gerar_token(usuario)
        return jsonify({
            'message': 'Login bem-sucedido.',
            'token': token
        }), 200
    else:
        return jsonify({'message': 'Senha incorreta.'}), 401

@app.route('/consulta', methods=['POST'])
@token_requerido
def consulta(current_user):
    data = request.json
    consulta_sucedida = data.get('consulta_sucedida', False)

    if not verificar_limite_diario(current_user):
        return jsonify({'message': 'Limite de 10 consultas diárias atingido.'}), 403

    current_user.consultas_hoje += 1
    current_user.consultas_totais += 1

    if consulta_sucedida:
        current_user.saldo += 1.0
        msg = 'Consulta realizada com sucesso. Saldo incrementado em R$1.'
    else:
        msg = 'Consulta não sucedida. Nenhum valor adicionado ao saldo.'

    db.session.commit()

    return jsonify({
        'message': msg,
        'consultas_hoje': current_user.consultas_hoje,
        'consultas_totais': current_user.consultas_totais,
        'saldo': current_user.saldo
    }), 200

@app.route('/usuario', methods=['GET'])
@token_requerido
def get_usuario(current_user):
    return jsonify({
        'id': current_user.id,
        'nome': current_user.nome,
        'cpf': current_user.cpf,
        'email': current_user.email,
        'numero_celular': current_user.numero_celular,
        'consultas_hoje': current_user.consultas_hoje,
        'consultas_totais': current_user.consultas_totais,
        'saldo': current_user.saldo,
        'codigo_indicacao': current_user.codigo_indicacao
    }), 200

@app.route('/consulta/<placa>', methods=['GET'])
@token_requerido
def consultar_placa(current_user, placa):
    # Verificar limite diário
    if not verificar_limite_diario(current_user):
        return jsonify({'message': 'Limite de 10 consultas diárias atingido.'}), 403

    try:
        # Fazer a requisição para a API externa
        response = requests.get(f'https://sweet-cake-27b5.daniel-jmendes2.workers.dev/{placa}')
        data = response.json()

        if data['status'] == 'success':
            return jsonify(data['dados']), 200
        else:
            return jsonify({'message': 'Placa não encontrada'}), 404

    except Exception as e:
        print(f"Erro na consulta: {str(e)}")
        return jsonify({'message': 'Erro ao consultar placa'}), 500

# -----------------------------------------------------------------------------
# Iniciar a aplicação
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
