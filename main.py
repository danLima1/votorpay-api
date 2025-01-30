from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import jwt
import datetime
from functools import wraps
import requests
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import time

app = Flask(__name__)

# Configuração do CORS mais permissiva
CORS(app, resources={
    r"/*": {
        "origins": ["http://127.0.0.1:5500", "https://votopayad.vercel.app"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
        "max_age": 600
    }
})

# Middleware para tratar preflight requests
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", request.headers.get("Origin", "*"))
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        response.headers.add("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        response.headers.add("Access-Control-Max-Age", "600")
        return response

# -----------------------------------------------------------------------------
# Configurações
# -----------------------------------------------------------------------------
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:POqEhF0Uz8N1IPQk@maliciously-upward-kelpie.data-1.use1.tembo.io:5432/postgres'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'fa0b66aedea910162f3bdb38c72817923e3807a53090d4683d50e00337ea86c4'

# Configurações do SMTP
SMTP_SERVER = "smtp.mailgun.org"
SMTP_PORT = 587
SMTP_USERNAME = "teste42@typebot.searchapi.shop"
SMTP_PASSWORD = "Daniel30055@"

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
    total_indicacoes = db.Column(db.Integer, default=0)
    usuarios_indicados = db.relationship('Usuario', backref=db.backref('indicador', remote_side=[id]), lazy='dynamic')
    reset_token = db.Column(db.String(100), unique=True, nullable=True)
    reset_token_expiracao = db.Column(db.DateTime, nullable=True)
    role = db.Column(db.String(20), default='sem_vip')
    data_expiracao_vip = db.Column(db.DateTime, nullable=True)
    ultima_transacao_id = db.Column(db.String(100), nullable=True)

    consultas_hoje = db.Column(db.Integer, default=0)
    data_ultima_consulta = db.Column(db.Date, default=datetime.date.today())
    consultas_totais = db.Column(db.Integer, default=0)
    saldo = db.Column(db.Float, default=0.0)
    ganhos_hoje = db.Column(db.Float, default=0)

class CartaoCredito(db.Model):
    __tablename__ = 'cartao_credito'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)
    renda_mensal = db.Column(db.Float, nullable=False)
    profissao = db.Column(db.String(100), nullable=False)
    data_nascimento = db.Column(db.Date, nullable=False)
    negativado = db.Column(db.Boolean, nullable=False)
    status = db.Column(db.String(20), nullable=False)
    cep = db.Column(db.String(10), nullable=False)
    rua = db.Column(db.String(100), nullable=False)
    numero = db.Column(db.String(10), nullable=False)
    complemento = db.Column(db.String(100), nullable=True)
    cidade = db.Column(db.String(100), nullable=False)
    estado = db.Column(db.String(2), nullable=False)
    data_solicitacao = db.Column(db.DateTime, nullable=False)
    data_atualizacao = db.Column(db.DateTime, nullable=False)

# -----------------------------------------------------------------------------
# Funções auxiliares
# -----------------------------------------------------------------------------
def token_requerido(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "OPTIONS":
            return jsonify({}), 200

        token = None
        auth_header = request.headers.get('Authorization', '')

        if auth_header:
            try:
                if auth_header.startswith('Bearer '):
                    token = auth_header.split(' ')[1]
                else:
                    token = auth_header
            except Exception as e:
                return jsonify({'message': 'Token inválido'}), 401

        if not token:
            return jsonify({'message': 'Token não fornecido'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Usuario.query.get(data['id'])
            if not current_user:
                return jsonify({'message': 'Usuário não encontrado'}), 404
                
            return f(current_user, *args, **kwargs)
            
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido'}), 401
        except Exception as e:
            return jsonify({'message': 'Erro na autenticação'}), 401
            
    return decorated

def gerar_token(usuario):
    payload = {
        'id': usuario.id,
        'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=24)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token

def verificar_limite_diario(usuario):
    try:
        # Obtém a data atual no timezone de Brasília
        tz_br = datetime.timezone(datetime.timedelta(hours=-3))
        hoje = datetime.datetime.now(tz_br).date()
        
        # Garantir que data_ultima_consulta seja um objeto date
        ultima_consulta = usuario.data_ultima_consulta
        if isinstance(ultima_consulta, datetime.datetime):
            ultima_consulta = ultima_consulta.date()
        
        if ultima_consulta != hoje:
            usuario.data_ultima_consulta = hoje
            usuario.consultas_hoje = 0
            usuario.ganhos_hoje = 0
            db.session.commit()

        # Verificar se o VIP expirou
        agora = datetime.datetime.now(datetime.UTC)
        if usuario.role != 'sem_vip' and usuario.data_expiracao_vip:
            # Garantir que a data de expiração tenha timezone
            data_expiracao = usuario.data_expiracao_vip
            if data_expiracao.tzinfo is None:
                data_expiracao = data_expiracao.replace(tzinfo=datetime.UTC)
            
            if data_expiracao < agora:
                usuario.role = 'sem_vip'
                usuario.data_expiracao_vip = None
                db.session.commit()
                print(f"VIP expirado: Usuário {usuario.nome} (CPF: {usuario.cpf})")

        # Definir limite baseado no VIP
        limites_diarios = {
            'sem_vip': 10,
            'vip1': 30,
            'vip2': 50,
            'vip3': 100
        }
        limite = limites_diarios.get(usuario.role, 10)

        return usuario.consultas_hoje < limite
        
    except Exception as e:
        print(f"Erro ao verificar limite diário: {str(e)}")
        return False

def enviar_email_reset_senha(email, token):
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = email
        msg['Subject'] = "Recuperação de Senha - VotorPay"

        link = f"https://votopayad.vercel.app/auth.html?token={token}"
        corpo = f"""
        <html>
            <body>
                <h2>Recuperação de Senha - VotorPay</h2>
                <p>Você solicitou a recuperação de senha. Clique no link abaixo para redefinir sua senha:</p>
                <p><a href="{link}">Clique aqui para redefinir sua senha</a></p>
                <p>Se você não solicitou esta recuperação, ignore este email.</p>
                <p>O link expira em 1 hora.</p>
            </body>
        </html>
        """

        msg.attach(MIMEText(corpo, 'html'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Erro ao enviar email: {str(e)}")
        return False

def verificar_pagamento_blackpay(transaction_id):
    try:
        # Configurações da BlackPay
        publicKey = 'votopayoficial_zt03ro1mjxej5tx6'
        secretKey = '7436pm952nxdcmq0motadjryc4k2guk7ohlb683460nceepdjmgq08nr5i6y07qq'
        
        # URL da API
        url = f"https://app.blackpay.io/api/v1/gateway/transactions?id={transaction_id}"
        
        # Headers
        headers = {
            'Accept': 'application/json',
            'x-public-key': publicKey,
            'x-secret-key': secretKey
        }
        
        # Fazer requisição
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Lança exceção para status codes de erro
        
        # Parse da resposta
        payment_data = response.json()
        print(f"Resposta da BlackPay: {payment_data}")
        
        return payment_data.get('status', 'UNKNOWN')
        
    except requests.exceptions.RequestException as e:
        print(f"Erro na requisição à BlackPay: {str(e)}")
        raise Exception(f"Erro ao verificar pagamento: {str(e)}")

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
        indicador.total_indicacoes += 1

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
        indicador.saldo += 25.0
    
    db.session.commit()

    return jsonify({'message': 'Usuário cadastrado com sucesso!'}), 201

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        cpf = data.get('cpf')
        senha = data.get('senha')

        if not cpf or not senha:
            return jsonify({'message': 'CPF e senha são obrigatórios.'}), 400

        usuario = Usuario.query.filter_by(cpf=cpf).first()
        if usuario and bcrypt.check_password_hash(usuario.senha, senha):
            token = jwt.encode({
                'id': usuario.id,
                'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            
            print(f"Token gerado para usuário {usuario.nome} (CPF: {usuario.cpf})")
            
            return jsonify({
                'token': token,
                'user': {
                    'id': usuario.id,
                    'nome': usuario.nome,
                    'cpf': usuario.cpf,
                    'role': usuario.role
                }
            }), 200
        return jsonify({'message': 'CPF ou senha inválidos.'}), 401
    except Exception as e:
        print(f"Erro no login: {str(e)}")
        return jsonify({'message': 'Erro ao realizar login'}), 500

@app.route('/consulta', methods=['POST'])
@token_requerido
def consulta(current_user):
    try:
        print(f"Iniciando consulta para usuário: {current_user.nome} (ID: {current_user.id})")
        data = request.get_json()
        print(f"Dados recebidos: {data}")
        
        if data is None:
            print("Dados não fornecidos")
            return jsonify({'message': 'Dados não fornecidos'}), 400
            
        consulta_sucedida = data.get('consulta_sucedida')
        dados_veiculo = data.get('dados_veiculo')
        
        print(f"Consulta sucedida: {consulta_sucedida}")
        print(f"Dados do veículo: {dados_veiculo}")

        # Verificar limite diário
        if not verificar_limite_diario(current_user):
            print(f"Limite diário atingido para usuário {current_user.nome}")
            return jsonify({'message': 'Limite diário de consultas atingido'}), 403

        try:
            # Definir limites e ganhos baseados no VIP
            limites_diarios = {
                'sem_vip': 10,
                'vip1': 30,
                'vip2': 50,
                'vip3': 100
            }

            ganhos_por_consulta = {
                'sem_vip': 1.0,
                'vip1': 1.75,
                'vip2': 2.50,
                'vip3': 5.0
            }

            limite_diario = limites_diarios.get(current_user.role, 10)
            ganho_por_consulta = ganhos_por_consulta.get(current_user.role, 1.0)

            current_user.consultas_hoje += 1
            current_user.consultas_totais += 1

            if consulta_sucedida:
                current_user.saldo += ganho_por_consulta
                current_user.ganhos_hoje += ganho_por_consulta

                # Bônus para VIP Diamond (vip3) a cada 100 consultas
                if current_user.role == 'vip3' and current_user.consultas_totais % 100 == 0:
                    current_user.saldo += 25.0
                    msg = f'Consulta realizada com sucesso. Saldo incrementado em R${ganho_por_consulta}. Bônus de R$25,00 por atingir 100 consultas!'
                else:
                    msg = f'Consulta realizada com sucesso. Saldo incrementado em R${ganho_por_consulta}.'
            else:
                msg = 'Consulta não sucedida. Nenhum valor adicionado ao saldo.'

            db.session.commit()
            print(f"Consulta finalizada com sucesso: {msg}")

            return jsonify({
                'message': msg,
                'consultas_hoje': current_user.consultas_hoje,
                'consultas_totais': current_user.consultas_totais,
                'saldo': current_user.saldo,
                'ganhos_hoje': current_user.ganhos_hoje,
                'limite_diario': limite_diario,
                'ganho_por_consulta': ganho_por_consulta
            }), 200

        except Exception as e:
            print(f"Erro ao processar dados da consulta: {str(e)}")
            db.session.rollback()
            return jsonify({'message': 'Erro ao processar dados da consulta'}), 500
            
    except Exception as e:
        print(f"Erro na rota de consulta: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Erro ao processar consulta'}), 500

@app.route('/usuario', methods=['GET'])
@token_requerido
def get_usuario(current_user):
    try:
        # Log para debug
        print("Headers recebidos:", dict(request.headers))
        
        # Verificar se o VIP expirou
        agora = datetime.datetime.now(datetime.UTC)
        if current_user.role != 'sem_vip' and current_user.data_expiracao_vip:
            # Garantir que a data de expiração tenha timezone
            data_expiracao = current_user.data_expiracao_vip
            if data_expiracao.tzinfo is None:
                data_expiracao = data_expiracao.replace(tzinfo=datetime.UTC)
                
            if data_expiracao < agora:
                current_user.role = 'sem_vip'
                current_user.data_expiracao_vip = None
                db.session.commit()
                print(f"VIP expirado para usuário {current_user.nome}")

        usuarios_indicados = [{
            'id': u.id,
            'nome': u.nome,
            'data_cadastro': u.data_cadastro.strftime('%d/%m/%Y') if hasattr(u, 'data_cadastro') else None
        } for u in current_user.usuarios_indicados.all()]

        # Calcular dias restantes com segurança
        dias_restantes = 0
        if current_user.data_expiracao_vip:
            data_expiracao = current_user.data_expiracao_vip
            if data_expiracao.tzinfo is None:
                data_expiracao = data_expiracao.replace(tzinfo=datetime.UTC)
            if data_expiracao > agora:
                dias_restantes = (data_expiracao - agora).days

        return jsonify({
            'id': current_user.id,
            'nome': current_user.nome,
            'cpf': current_user.cpf,
            'email': current_user.email,
            'numero_celular': current_user.numero_celular,
            'consultas_hoje': current_user.consultas_hoje,
            'consultas_totais': current_user.consultas_totais,
            'saldo': current_user.saldo,
            'codigo_indicacao': current_user.codigo_indicacao,
            'total_indicacoes': current_user.total_indicacoes,
            'usuarios_indicados': usuarios_indicados,
            'ganhos_hoje': current_user.ganhos_hoje,
            'role': current_user.role,
            'vip_expira_em': current_user.data_expiracao_vip.isoformat() if current_user.data_expiracao_vip else None,
            'dias_restantes_vip': dias_restantes
        }), 200
    except Exception as e:
        print(f"Erro ao obter dados do usuário: {str(e)}")
        return jsonify({'message': 'Erro ao obter dados do usuário'}), 500

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

@app.route('/esqueci-senha', methods=['POST'])
def esqueci_senha():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({'message': 'Email é obrigatório.'}), 400

    usuario = Usuario.query.filter_by(email=email).first()
    if not usuario:
        return jsonify({'message': 'Email não encontrado.'}), 404

    # Gerar token único
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=50))
    
    # Salvar token e data de expiração
    usuario.reset_token = token
    usuario.reset_token_expiracao = datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
    
    try:
        db.session.commit()
        if enviar_email_reset_senha(email, token):
            return jsonify({'message': 'Email de recuperação enviado com sucesso.'}), 200
        else:
            return jsonify({'message': 'Erro ao enviar email de recuperação.'}), 500
    except:
        db.session.rollback()
        return jsonify({'message': 'Erro ao processar solicitação.'}), 500

@app.route('/reset-senha', methods=['POST'])
def reset_senha():
    data = request.json
    token = data.get('token')
    nova_senha = data.get('nova_senha')

    if not all([token, nova_senha]):
        return jsonify({'message': 'Token e nova senha são obrigatórios.'}), 400

    usuario = Usuario.query.filter_by(reset_token=token).first()
    if not usuario:
        return jsonify({'message': 'Token inválido.'}), 400

    # Verificar se o token expirou
    agora = datetime.datetime.now(datetime.UTC)
    if not usuario.reset_token_expiracao or usuario.reset_token_expiracao.replace(tzinfo=datetime.UTC) < agora:
        return jsonify({'message': 'Token expirado.'}), 400

    # Atualizar senha
    usuario.senha = bcrypt.generate_password_hash(nova_senha).decode('utf-8')
    usuario.reset_token = None
    usuario.reset_token_expiracao = None

    try:
        db.session.commit()
        return jsonify({'message': 'Senha atualizada com sucesso.'}), 200
    except:
        db.session.rollback()
        return jsonify({'message': 'Erro ao atualizar senha.'}), 500

@app.route('/atualizar-vip', methods=['POST'])
@token_requerido
def atualizar_vip(current_user):
    try:
        # Log dos dados recebidos
        print("Dados recebidos:", request.json)
        
        # Obter dados da requisição
        data = request.json
        transaction_id = data.get('transaction_id')
        vip_type = data.get('vip_type')
        
        if not transaction_id or not vip_type:
            return jsonify({'status': 'error', 'message': 'Dados incompletos'}), 400
            
        # Verificar status do pagamento na BlackPay
        try:
            payment_status = verificar_pagamento_blackpay(transaction_id)
            print(f"Status do pagamento: {payment_status}")
            
            if payment_status != 'COMPLETED':
                return jsonify({'status': 'error', 'message': f'Status do pagamento inválido: {payment_status}'}), 400
                
        except Exception as e:
            print(f"Erro ao verificar pagamento na BlackPay: {str(e)}")
            return jsonify({'status': 'error', 'message': 'Erro ao verificar pagamento'}), 500
            
        # Atualizar VIP do usuário
        if vip_type in ['vip1', 'vip2', 'vip3']:
            current_user.role = vip_type
            current_user.data_expiracao_vip = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=7)
            current_user.ultima_transacao_id = transaction_id
            
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'message': 'VIP atualizado com sucesso',
                'vip_type': vip_type,
                'expira_em': current_user.data_expiracao_vip.isoformat()
            }), 200
        else:
            return jsonify({'status': 'error', 'message': 'Tipo de VIP inválido'}), 400
            
    except Exception as e:
        print(f"Erro ao atualizar VIP: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Erro interno ao atualizar VIP'}), 500

@app.route('/webhook/blackpay', methods=['POST'])
def blackpay_webhook():
    try:
        # Log do payload recebido
        print("Webhook recebido:", request.json)
        
        # Dados da transação
        transaction_data = request.json
        
        # Verificar se é uma notificação de pagamento
        if transaction_data.get('event') == 'TRANSACTION_PAID':
            # Extrair dados necessários
            transaction_id = transaction_data.get('transaction', {}).get('id')
            client_data = transaction_data.get('client', {})
            cpf = client_data.get('cpf')
            
            # Extrair tipo de VIP do nome do produto
            order_items = transaction_data.get('orderItems', [])
            if not order_items:
                return jsonify({'status': 'error', 'message': 'Nenhum item no pedido'}), 400
                
            product_name = order_items[0].get('product', {}).get('name', '').lower()
            if 'vip1' in product_name:
                vip_type = 'vip1'
            elif 'vip2' in product_name:
                vip_type = 'vip2'
            elif 'vip3' in product_name:
                vip_type = 'vip3'
            else:
                return jsonify({'status': 'error', 'message': 'Tipo de VIP não identificado'}), 400
            
            print(f"Pagamento confirmado - Transaction ID: {transaction_id}, CPF: {cpf}, VIP Type: {vip_type}")
            
            if not transaction_id or not cpf:
                print("Dados incompletos no webhook")
                return jsonify({'status': 'error', 'message': 'Dados incompletos'}), 400
            
            # Encontrar usuário pelo CPF
            usuario = Usuario.query.filter_by(cpf=cpf).first()
            if not usuario:
                return jsonify({'status': 'error', 'message': 'Usuário não encontrado'}), 404

            # Atualizar VIP do usuário
            usuario.role = vip_type
            usuario.data_expiracao_vip = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=7)
            usuario.ultima_transacao_id = transaction_id
            db.session.commit()
            
            print(f"VIP atualizado: Usuário {usuario.nome} (CPF: {usuario.cpf}) -> {vip_type}")
            return jsonify({
                'status': 'success',
                'message': 'VIP atualizado com sucesso',
                'user_id': usuario.id,
                'new_role': vip_type,
                'expira_em': usuario.data_expiracao_vip.isoformat()
            }), 200
        
        return jsonify({'status': 'success'}), 200
        
    except Exception as e:
        print(f"Erro no webhook: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Ajuste nos endpoints do cartão
@app.route('/solicitar-cartao', methods=['POST', 'OPTIONS'])
@token_requerido
def solicitar_cartao(current_user):
    try:
        # Verificar se já existe uma solicitação
        existing_request = CartaoCredito.query.filter_by(user_id=current_user.id).first()
        if existing_request:
            return jsonify({
                "status": existing_request.status, 
                "message": "Você já possui uma solicitação de cartão"
            }), 200

        # Obter dados do corpo da requisição
        data = request.json
        
        # Criar objeto de solicitação
        solicitacao = CartaoCredito(
            user_id=current_user.id,
            renda_mensal=float(data["renda_mensal"]),
            profissao=data["profissao"],
            data_nascimento=datetime.datetime.strptime(data["data_nascimento"], '%Y-%m-%d').date(),
            negativado=data["negativado"],
            status="em_analise",
            cep=data["endereco"]["cep"],
            rua=data["endereco"]["rua"],
            numero=data["endereco"]["numero"],
            complemento=data["endereco"]["complemento"],
            cidade=data["endereco"]["cidade"],
            estado=data["endereco"]["estado"],
            data_solicitacao=datetime.datetime.now(datetime.UTC),
            data_atualizacao=datetime.datetime.now(datetime.UTC)
        )

        db.session.add(solicitacao)
        db.session.commit()

        # Agendar análise automática após 30 minutos
        def analisar_cartao():
            with app.app_context():
                time.sleep(1800)  # 30 minutos
                solicitacao = CartaoCredito.query.filter_by(
                    user_id=current_user.id,
                    status="em_analise"
                ).first()

                if solicitacao:
                    # 50% de chance de aprovação
                    aprovado = random.choice([True, False])
                    solicitacao.status = "aprovado" if aprovado else "reprovado"
                    solicitacao.data_atualizacao = datetime.datetime.now(datetime.UTC)
                    db.session.commit()

        thread = threading.Thread(target=analisar_cartao)
        thread.start()

        return jsonify({
            "status": "em_analise", 
            "message": "Solicitação recebida com sucesso"
        }), 200

    except Exception as e:
        db.session.rollback()
        print(f"Erro ao solicitar cartão: {str(e)}")
        return jsonify({"message": f"Erro ao processar solicitação: {str(e)}"}), 500

@app.route('/status-cartao', methods=['GET', 'OPTIONS'])
@token_requerido
def status_cartao(current_user):
    if request.method == 'OPTIONS':
        return jsonify({}), 200
        
    try:
        # Buscar status da solicitação
        solicitacao = CartaoCredito.query.filter_by(user_id=current_user.id).first()
        
        if not solicitacao:
            return jsonify({"tem_solicitacao": False}), 200

        # Calcular tempo restante se estiver em análise
        tempo_restante = None
        if solicitacao.status == "em_analise":
            tempo_decorrido = datetime.datetime.now(datetime.UTC) - solicitacao.data_solicitacao
            tempo_restante = max(0, 1800 - tempo_decorrido.total_seconds())  # 1800 segundos = 30 minutos

        return jsonify({
            "tem_solicitacao": True,
            "status": solicitacao.status,
            "tempo_restante": tempo_restante,
            "data_solicitacao": solicitacao.data_solicitacao,
            "data_atualizacao": solicitacao.data_atualizacao
        }), 200

    except Exception as e:
        print(f"Erro ao verificar status do cartão: {str(e)}")
        return jsonify({"message": f"Erro ao verificar status: {str(e)}"}), 500

# -----------------------------------------------------------------------------
# Iniciar a aplicação
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
