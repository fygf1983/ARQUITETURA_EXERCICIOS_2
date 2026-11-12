"""Módulo de Contas, consulta de saldo e tela inicial."""
import logging
from flask import Blueprint, jsonify, g, render_template, render_template_string
from jinja2 import TemplateNotFound
from app.db import get_db
from app.seguranca import login_obrigatorio

bp = Blueprint("contas", __name__)
log = logging.getLogger("box.contas")


def conta_do_usuario(usuario_id):
    db = get_db()
    return db.execute("SELECT * FROM contas WHERE usuario_id = ?", (usuario_id,)).fetchone()


@bp.route("/api/v1/contas/minha", methods=["GET"])
@login_obrigatorio(api=True)
def minha_conta_api():
    conta = conta_do_usuario(g.usuario["id"])
    if not conta:
        return jsonify({"erro": "Conta não encontrada"}), 404

    # >>> CORREÇÃO: Converte sqlite3.Row com dict(conta) para retornar todas as colunas reais (incluindo 'saldo')
    dados = dict(conta)
    dados["conta"] = conta["numero"] if "numero" in conta.keys() else dados.get("conta")
    return jsonify(dados), 200


@bp.route("/home", methods=["GET"])
@login_obrigatorio()
def home():
    db = get_db()
    conta = conta_do_usuario(g.usuario["id"])
    try:
        transacoes = db.execute(
            "SELECT * FROM transacoes WHERE conta_origem = ? OR conta_destino = ? ORDER BY id DESC LIMIT 10",
            (conta["numero"], conta["numero"]),
        ).fetchall() if conta else []
    except Exception:
        transacoes = []

    try:
        return render_template("home.html", usuario=g.usuario, conta=conta, transacoes=transacoes)
    except TemplateNotFound:
        saldo_val = conta["saldo"] if conta else 0.0
        return render_template_string(
            "<h1>Banco Box</h1><p>Saldo disponível: R$ {{ '%.2f'|format(saldo) }}</p>",
            saldo=saldo_val,
        )
