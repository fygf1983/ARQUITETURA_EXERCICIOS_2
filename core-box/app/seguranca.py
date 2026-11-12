"""Módulo de Segurança, Autenticação JWT, Hash de Senhas e Decoradores de Acesso."""
import datetime
import functools
import hashlib
import jwt
from flask import current_app, g, jsonify, redirect, request
from werkzeug.security import generate_password_hash, check_password_hash
from app.db import get_db


# >>> CORREÇÃO TM-12: Substitui MD5 puro por hash seguro com salt (Werkzeug PBKDF2/Scrypt)
def hash_senha(senha: str) -> str:
    return generate_password_hash(senha)


# >>> CORREÇÃO TM-12: Valida hashes modernos e mantém compatibilidade com hashes migrados do seed
def verificar_senha(senha: str, senha_hash: str) -> bool:
    if not senha_hash:
        return False
    if senha_hash.startswith(("pbkdf2:", "scrypt:", "argon2:")):
        if check_password_hash(senha_hash, senha):
            return True
        # Suporte para hashes MD5 do seed que foram encapsulados com generate_password_hash
        md5_legado = hashlib.md5(senha.encode()).hexdigest()
        return check_password_hash(senha_hash, md5_legado)
    return senha_hash == hashlib.md5(senha.encode()).hexdigest()


def gerar_token_jwt(usuario) -> str:
    agora = datetime.datetime.now(datetime.UTC)
    # >>> CORREÇÃO: Usa sempre JWT_SECRET (com fallback para SECRET_KEY) de forma consistente
    secret = current_app.config.get("JWT_SECRET") or current_app.config.get("SECRET_KEY", "dev-secret")
    exp_horas = current_app.config.get("JWT_EXPIRACAO_HORAS", 8)

    # >>> CORREÇÃO: 'sub' convertido para str(usuario["id"]) (obrigatório no PyJWT 2.x / Python 3.13)
    payload = {
        "sub": str(usuario["id"]),
        "cpf": usuario["cpf"] if "cpf" in usuario.keys() else "",
        "nome": usuario["nome"] if "nome" in usuario.keys() else "",
        "perfil": usuario["perfil"] if "perfil" in usuario.keys() else "cliente",
        "iat": agora,
        "exp": agora + datetime.timedelta(hours=exp_horas),
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


# Aliases para manter compatibilidade caso outros módulos chamem pelo nome original
emitir_token = gerar_token_jwt
criar_token = gerar_token_jwt


def _token_da_requisicao():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.cookies.get("box_token")


def usuario_atual():
    token = _token_da_requisicao()
    if not token:
        return None
    try:
        # >>> CORREÇÃO: Decodifica usando exatamente a mesma chave JWT_SECRET usada em gerar_token_jwt
        secret = current_app.config.get("JWT_SECRET") or current_app.config.get("SECRET_KEY", "dev-secret")
        dados = jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    return get_db().execute("SELECT * FROM usuarios WHERE id = ?", (int(dados["sub"]),)).fetchone()


def login_obrigatorio(perfil=None, api=False):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            usuario = usuario_atual()
            usuario_perfil = usuario["perfil"] if usuario and "perfil" in usuario.keys() else None
            if usuario is None or (perfil and usuario_perfil != perfil):
                if api or request.path.startswith("/api/"):
                    return jsonify({"erro": "não autenticado"}), 401
                destino = "/backoffice/login" if request.path.startswith("/backoffice") else "/login"
                return redirect(destino)
            g.usuario = usuario
            return fn(*args, **kwargs)
        return wrapper
    return deco
