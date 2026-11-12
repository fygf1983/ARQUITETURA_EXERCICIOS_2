"""Autenticação, login, controle de tentativas e recuperação de senha."""
import datetime
import logging
import random

from flask import Blueprint, render_template, request, jsonify, redirect, make_response

from app import auditoria
from app.db import get_db
from app.seguranca import gerar_token_jwt, hash_senha, verificar_senha

bp = Blueprint("auth", __name__)
log = logging.getLogger("box.auth")


# >>> CORREÇÃO TM-01: Cria a tabela de controle de força bruta caso não exista no banco de testes
def _inicializar_tabela_bloqueio(db):
    db.execute(
        "CREATE TABLE IF NOT EXISTS controle_tentativas ("
        "cpf TEXT PRIMARY KEY, "
        "tentativas INTEGER NOT NULL DEFAULT 0, "
        "bloqueado_ate TEXT)"
    )


def _esta_bloqueado(db, cpf: str) -> bool:
    _inicializar_tabela_bloqueio(db)
    agora = datetime.datetime.now(datetime.UTC).isoformat()
    reg = db.execute(
        "SELECT tentativas, bloqueado_ate FROM controle_tentativas WHERE cpf = ?", (cpf,)
    ).fetchone()
    if reg and reg["bloqueado_ate"] and reg["bloqueado_ate"] > agora:
        return True
    return False


def _registrar_falha(db, cpf: str):
    _inicializar_tabela_bloqueio(db)
    reg = db.execute("SELECT tentativas FROM controle_tentativas WHERE cpf = ?", (cpf,)).fetchone()
    total = (reg["tentativas"] + 1) if reg else 1
    bloqueado_ate = None
    # >>> CORREÇÃO TM-01: Após 5 falhas seguidas, bloqueia o CPF temporariamente (HTTP 429)
    if total >= 5:
        bloqueado_ate = (datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=15)).isoformat()
    db.execute(
        "INSERT OR REPLACE INTO controle_tentativas (cpf, tentativas, bloqueado_ate) VALUES (?, ?, ?)",
        (cpf, total, bloqueado_ate),
    )
    db.commit()


def _limpar_falhas(db, cpf: str):
    _inicializar_tabela_bloqueio(db)
    db.execute("DELETE FROM controle_tentativas WHERE cpf = ?", (cpf,))
    db.commit()


@bp.route("/api/v1/auth/login", methods=["POST"])
def login_api():
    dados = request.get_json(force=True, silent=True) or {}
    cpf = (dados.get("cpf") or "").strip()
    senha = dados.get("senha") or ""

    db = get_db()

    # >>> CORREÇÃO TM-01: Verifica o bloqueio antes de validar a senha e retorna HTTP 429
    if _esta_bloqueado(db, cpf):
        return jsonify({"erro": "Muitas tentativas inválidas. Conta temporariamente bloqueada."}), 429

    usuario = db.execute("SELECT * FROM usuarios WHERE cpf = ?", (cpf,)).fetchone()

    # >>> CORREÇÃO TM-23 e TM-12: Mensagem idêntica para CPF inexistente ou senha incorreta
    if not usuario or not verificar_senha(senha, usuario["senha_hash"]):
        if cpf:
            _registrar_falha(db, cpf)
        return jsonify({"erro": "Credenciais inválidas."}), 401

    _limpar_falhas(db, cpf)

    # >>> CORREÇÃO: Usa gerar_token_jwt de app.seguranca (com JWT_SECRET correto)
    token = gerar_token_jwt(usuario)
    return jsonify({"token": token, "nome": usuario["nome"]}), 200


@bp.route("/login", methods=["GET", "POST"])
def login_web():
    if request.method == "GET":
        return render_template("login.html")

    cpf = request.form.get("cpf", "").strip()
    senha = request.form.get("senha", "")
    db = get_db()

    if _esta_bloqueado(db, cpf):
        return render_template("login.html", erro="Muitas tentativas. Conta temporariamente bloqueada."), 429

    usuario = db.execute("SELECT * FROM usuarios WHERE cpf = ?", (cpf,)).fetchone()
    if not usuario or not verificar_senha(senha, usuario["senha_hash"]):
        if cpf:
            _registrar_falha(db, cpf)
        return render_template("login.html", erro="Credenciais inválidas."), 401

    _limpar_falhas(db, cpf)

    # >>> CORREÇÃO: Grava o token no cookie 'box_token' esperado por app/seguranca.py no GET /home
    token = gerar_token_jwt(usuario)
    resp = make_response(redirect("/home"))
    resp.set_cookie("box_token", token, httponly=True, samesite="Lax")
    return resp


@bp.route("/logout", methods=["GET", "POST"])
def logout():
    resp = make_response(redirect("/login"))
    resp.delete_cookie("box_token")
    return resp


@bp.route("/recuperar", methods=["GET", "POST"])
def recuperar():
    db = get_db()
    if request.method == "GET":
        return render_template("recuperar.html", etapa="dados")

    cpf = request.form.get("cpf", "").strip()
    nascimento = request.form.get("nascimento", "").strip()

    usuario = db.execute("SELECT * FROM usuarios WHERE cpf = ? AND nascimento = ?", (cpf, nascimento)).fetchone()
    if not usuario:
        return render_template("recuperar.html", etapa="dados", erro="Dados inválidos."), 400

    codigo = f"{random.SystemRandom().randint(0, 9999):04d}"
    expira = (datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=15)).isoformat()
    db.execute("INSERT OR REPLACE INTO otp (cpf, codigo, expira_em) VALUES (?, ?, ?)", (cpf, codigo, expira))
    db.commit()

    auditoria.registrar(cpf, "OTP_ENVIADO", {"celular": usuario["celular"]})
    return render_template("recuperar.html", etapa="codigo", cpf=cpf, celular=usuario["celular"])


@bp.route("/recuperar/confirmar", methods=["POST"])
def recuperar_confirmar():
    db = get_db()
    cpf = request.form.get("cpf", "").strip()
    codigo_informado = request.form.get("codigo", "").strip()
    nova_senha = request.form.get("nova_senha", "")

    otp = db.execute(
        "SELECT * FROM otp WHERE cpf = ? AND codigo = ? AND expira_em > ?",
        (cpf, codigo_informado, datetime.datetime.now(datetime.UTC).isoformat()),
    ).fetchone()
    if not otp:
        return render_template("recuperar.html", etapa="codigo", cpf=cpf, erro="Código inválido ou expirado."), 400

    # >>> CORREÇÃO TM-12: Salva nova senha usando hash seguro
    db.execute("UPDATE usuarios SET senha_hash = ? WHERE cpf = ?", (hash_senha(nova_senha), cpf))
    db.execute("DELETE FROM otp WHERE cpf = ?", (cpf,))
    db.commit()

    return render_template("recuperar.html", etapa="ok")
