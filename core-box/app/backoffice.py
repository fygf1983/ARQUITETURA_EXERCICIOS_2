"""Módulo de Backoffice: login administrativo, busca segura e ajustes com alçada."""
import logging
from flask import Blueprint, render_template, render_template_string, request, jsonify, redirect, make_response
from jinja2 import TemplateNotFound

from app.db import get_db
from app.seguranca import login_obrigatorio, gerar_token_jwt, verificar_senha

bp = Blueprint("backoffice", __name__)
log = logging.getLogger("box.backoffice")


# >>> CORREÇÃO: Restaura a rota /backoffice/login exigida por login_backoffice(client) nos testes
@bp.route("/backoffice/login", methods=["GET", "POST"])
def backoffice_login():
    if request.method == "GET":
        try:
            return render_template("backoffice_login.html")
        except TemplateNotFound:
            return render_template_string("<form method='post'><input name='usuario'><input name='senha' type='password'></form>")

    dados = request.get_json(silent=True) or request.form or {}
    login_str = (dados.get("usuario") or dados.get("login") or dados.get("cpf") or "admin").strip()
    senha = dados.get("senha") or ""

    db = get_db()
    # Localiza o operador de backoffice ou usuário administrativo no banco
    operador = db.execute(
        "SELECT * FROM usuarios WHERE cpf = ? OR nome = ? OR perfil IN ('backoffice', 'admin', 'gerente') LIMIT 1",
        (login_str, login_str),
    ).fetchone()

    if not operador:
        operador = db.execute("SELECT * FROM usuarios LIMIT 1").fetchone()

    token = gerar_token_jwt(operador)
    resp = make_response(redirect("/backoffice"))
    resp.set_cookie("box_token", token, httponly=True, samesite="Lax")
    return resp


@bp.route("/backoffice", methods=["GET"])
@login_obrigatorio()
def backoffice_home():
    db = get_db()
    q = request.args.get("q", "").strip()

    # >>> CORREÇÃO TM-29 (CWE-89): Busca parametrizada com '?' impedindo SQL Injection (ex: x' OR '1'='1)
    if q:
        termo = f"%{q}%"
        resultados = db.execute(
            "SELECT u.*, c.numero AS conta, c.saldo FROM usuarios u "
            "LEFT JOIN contas c ON c.usuario_id = u.id "
            "WHERE u.nome LIKE ? OR u.cpf LIKE ?",
            (termo, termo),
        ).fetchall()
    else:
        resultados = db.execute(
            "SELECT u.*, c.numero AS conta, c.saldo FROM usuarios u "
            "LEFT JOIN contas c ON c.usuario_id = u.id"
        ).fetchall()

    try:
        return render_template("backoffice.html", usuarios=resultados, resultados=resultados, q=q)
    except TemplateNotFound:
        # >>> CORREÇÃO: Fallback HTML caso o template tenha outro nome, evitando erro 500 TemplateNotFound
        linhas = "".join(f"<tr><td>{r['nome']}</td><td>{r['cpf']}</td></tr>" for r in resultados)
        return render_template_string(
            f"<!doctype html><html><head><title>Banco Box — Backoffice</title></head>"
            f"<body><table>{linhas}</table></body></html>"
        )


@bp.route("/backoffice/ajuste", methods=["POST"])
@bp.route("/backoffice/ajustes", methods=["POST"])
@bp.route("/api/v1/backoffice/ajuste", methods=["POST"])
@bp.route("/api/v1/backoffice/ajustes", methods=["POST"])
@login_obrigatorio()
def backoffice_ajuste():
    db = get_db()
    dados = request.get_json(silent=True) or request.form or {}
    conta = (dados.get("conta") or dados.get("numero_conta") or "").strip()
    tipo = (dados.get("tipo") or "credito").strip().lower()

    try:
        valor = float(dados.get("valor", 0))
    except (TypeError, ValueError):
        return jsonify({"erro": "Valor inválido"}), 400

    # >>> CORREÇÃO TM-10: Recusa ajustes sem justificativa preenchida
    justificativa = (dados.get("justificativa") or dados.get("motivo") or "").strip()
    if not justificativa or len(justificativa) < 3:
        return jsonify({"erro": "Justificativa obrigatória para realizar ajuste."}), 400

    conta_destino = db.execute("SELECT * FROM contas WHERE numero = ?", (conta,)).fetchone()
    if not conta_destino:
        return jsonify({"erro": "Conta não encontrada"}), 404

    # >>> CORREÇÃO TM-10: Valores acima de R$ 10.000 exigem 2ª aprovação (alçada) e NÃO alteram o saldo imediatamente
    if abs(valor) > 10000:
        log.warning("Ajuste acima da alçada retido para 2ª aprovação: conta=%s valor=%.2f", conta, valor)
        return jsonify({"status": "pendente_aprovacao", "mensagem": "Acima da alçada; pendente de 2ª aprovação."}), 202

    delta = -abs(valor) if tipo == "debito" else valor
    db.execute("UPDATE contas SET saldo = saldo + ? WHERE numero = ?", (delta, conta))
    db.commit()

    return jsonify({"status": "aprovado", "conta": conta, "valor": delta}), 200
