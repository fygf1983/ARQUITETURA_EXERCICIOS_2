"""Core Box – Core Bancário do Banco Box (versão de laboratório)."""
import logging
import traceback
from flask import Flask, redirect, make_response
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash

from app import config, db


def _migrar_senhas_md5(conn):
    """Converte senhas em MD5 puro do seed inicial para hash seguro com salt (TM-12)."""
    try:
        usuarios = conn.execute("SELECT id, senha_hash FROM usuarios").fetchall()
        alterou = False
        for u in usuarios:
            h = u["senha_hash"] or ""
            # Se for hash MD5 hexadecimal puro (32 caracteres sem prefixo de algoritmo)
            if len(h) == 32 and not h.startswith(("pbkdf2:", "scrypt:", "argon2:")):
                novo_hash = generate_password_hash(h)
                conn.execute("UPDATE usuarios SET senha_hash = ? WHERE id = ?", (novo_hash, u["id"]))
                alterou = True
        if alterou:
            conn.commit()
    except Exception:
        pass


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(config.Config)
    if test_config:
        app.config.update(test_config)

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    db.init_app(app)

    # >>> CORREÇÃO TM-12: Garante que qualquer conexão retornada por get_db() não tenha senhas em MD5 puro
    _get_db_original = db.get_db

    def _get_db_seguro():
        conn = _get_db_original()
        _migrar_senhas_md5(conn)
        return conn

    db.get_db = _get_db_seguro

    from app.auth import bp as auth_bp
    from app.contas import bp as contas_bp
    from app.pix import bp as pix_bp
    from app.backoffice import bp as backoffice_bp
    from app.onboarding import bp as onboarding_bp
    from app.api_interna import bp as interna_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(contas_bp)
    app.register_blueprint(pix_bp)
    app.register_blueprint(backoffice_bp)
    app.register_blueprint(onboarding_bp)
    app.register_blueprint(interna_bp)

    @app.route("/")
    def index():
        return redirect("/login")

    @app.route("/health")
    def health():
        return {"status": "ok", "app": "core-box"}

    @app.errorhandler(Exception)
    def erro_generico(exc):
        # >>> CORREÇÃO: Preserva códigos HTTP nativos do Flask (como 404 Not Found)
        if isinstance(exc, HTTPException):
            return make_response({"erro": exc.description}, exc.code)

        # >>> CORREÇÃO TM-07 (CWE-209): Registra o erro internamente, mas NÃO expõe stack trace nem arquivos .py ao cliente
        detalhe = traceback.format_exc()
        app.logger.error("Erro não tratado: %s", detalhe)
        return make_response({"erro": "Erro interno no processamento da requisição."}, 500)

    return app
