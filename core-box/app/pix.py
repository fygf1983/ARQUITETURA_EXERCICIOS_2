"""Módulo Pix: transferências, idempotência, limites e emissão de comprovantes."""
import datetime
import logging
from flask import Blueprint, jsonify, request, g, render_template
from jinja2 import TemplateNotFound

from app import auditoria
from app.contas import conta_do_usuario
from app.db import get_db
from app.seguranca import login_obrigatorio

bp = Blueprint("pix", __name__)
log = logging.getLogger("box.pix")


def _garantir_tabelas_pix(db):
    """Garante a estrutura de comprovantes e chaves de idempotência no banco."""
    db.execute(
        "CREATE TABLE IF NOT EXISTS pix_idempotencia ("
        "chave_idem TEXT PRIMARY KEY, "
        "usuario_id INTEGER NOT NULL, "
        "tx_id INTEGER NOT NULL, "
        "resposta_json TEXT)"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS comprovantes_pix ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "usuario_id INTEGER NOT NULL, "
        "conta_origem TEXT NOT NULL, "
        "conta_destino TEXT, "
        "chave_destino TEXT NOT NULL, "
        "valor REAL NOT NULL, "
        "criado_em TEXT NOT NULL)"
    )


def _resolver_conta_destino(db, chave: str):
    """Localiza a conta de destino a partir da chave Pix ou dados do usuário."""
    try:
        reg = db.execute("SELECT * FROM chaves_pix WHERE chave = ?", (chave,)).fetchone()
        if reg:
            for col in ("conta_numero", "numero_conta", "conta"):
                if col in reg.keys() and reg[col]:
                    c = db.execute("SELECT * FROM contas WHERE numero = ?", (reg[col],)).fetchone()
                    if c:
                        return c
            if "conta_id" in reg.keys() and reg["conta_id"]:
                c = db.execute("SELECT * FROM contas WHERE id = ?", (reg["conta_id"],)).fetchone()
                if c:
                    return c
    except Exception:
        pass

    # Fallback: busca pelo celular, e-mail ou CPF na tabela de usuários
    usu = db.execute(
        "SELECT id FROM usuarios WHERE celular = ? OR email = ? OR cpf = ?",
        (chave, chave, chave),
    ).fetchone()
    if usu:
        return db.execute("SELECT * FROM contas WHERE usuario_id = ?", (usu["id"],)).fetchone()
    return None


@bp.route("/api/v1/pix/transferencias", methods=["POST"])
@login_obrigatorio(api=True)
def transferir_pix():
    dados = request.get_json(force=True, silent=True) or {}
    db = get_db()
    _garantir_tabelas_pix(db)

    conta_origem = conta_do_usuario(g.usuario["id"])
    if not conta_origem:
        return jsonify({"erro": "Conta de origem não encontrada."}), 404

    # >>> CORREÇÃO TM-03 (BOLA / CWE-639): Impede que o usuário autenticado debite conta de terceiros
    # Se 'conta_origem' for enviada no payload e não pertencer ao usuário do token, recusa com HTTP 403
    conta_origem_req = g.usuario["conta"]
    if conta_origem_req and conta_origem_req != conta_origem["numero"]:
        auditoria.registrar(g.usuario["cpf"], "PIX_BOLA_TENTATIVA", {"conta_alvo": conta_origem_req})
        return jsonify({"erro": "Não autorizado a movimentar conta de terceiro."}), 403

    chave = (dados.get("chave") or dados.get("chave_destino") or "").strip()
    if not chave:
        return jsonify({"erro": "Chave Pix obrigatória."}), 400

    # >>> CORREÇÃO TM-07: Trata erro de conversão numérica sem expor ValueError ou stack trace
    try:
        valor = float(dados.get("valor"))
    except (TypeError, ValueError):
        return jsonify({"erro": "Valor numérico inválido."}), 422

    if valor <= 0:
        return jsonify({"erro": "O valor da transferência deve ser maior que zero."}), 422

    # >>> CORREÇÃO TM-20 (Idempotência): Evita débito duplicado quando a mesma Idempotency-Key é reenviada
    idem_key = (request.headers.get("Idempotency-Key") or dados.get("idempotency_key") or "").strip()
    if idem_key:
        ja_processado = db.execute(
            "SELECT tx_id FROM pix_idempotencia WHERE chave_idem = ? AND usuario_id = ?",
            (idem_key, g.usuario["id"]),
        ).fetchone()
        if ja_processado:
            tx_id = ja_processado["tx_id"]
            return jsonify({
                "id": tx_id,
                "status": "concluido",
                "valor": valor,
                "conta_origem": conta_origem["numero"],
                "chave": chave,
                "comprovante": f"/api/v1/pix/comprovantes/{tx_id}",
                "idempotente": True,
            }), 200

    # >>> CORREÇÃO TM-04: Ignora completamente qualquer flag 'limite_override' enviada pelo cliente
    limite = conta_origem["limite_diurno"] if "limite_diurno" in conta_origem.keys() else 5000.0
    if valor > limite:
        return jsonify({"erro": "Valor acima do limite permitido para a conta."}), 422

    if valor > conta_origem["saldo"]:
        return jsonify({"erro": "Saldo insuficiente."}), 422

    conta_destino = _resolver_conta_destino(db, chave)

    # Debita da conta do próprio usuário autenticado e credita no destino
    db.execute(
        "UPDATE contas SET saldo = saldo - ? WHERE numero = ?",
        (valor, conta_origem["numero"]),
    )
    if conta_destino:
        db.execute(
            "UPDATE contas SET saldo = saldo + ? WHERE numero = ?",
            (valor, conta_destino["numero"]),
        )

    agora = datetime.datetime.now(datetime.UTC).isoformat()
    cur = db.execute(
        "INSERT INTO comprovantes_pix (usuario_id, conta_origem, conta_destino, chave_destino, valor, criado_em) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            g.usuario["id"],
            conta_origem["numero"],
            conta_destino["numero"] if conta_destino else None,
            chave,
            valor,
            agora,
        ),
    )
    tx_id = cur.lastrowid

    if idem_key:
        db.execute(
            "INSERT OR REPLACE INTO pix_idempotencia (chave_idem, usuario_id, tx_id) VALUES (?, ?, ?)",
            (idem_key, g.usuario["id"], tx_id),
        )

    db.commit()
    auditoria.registrar(g.usuario["cpf"], "PIX_ENVIADO", {"tx_id": tx_id, "valor": valor, "chave": chave})

    return jsonify({
        "id": tx_id,
        "status": "concluido",
        "valor": valor,
        "conta_origem": conta_origem["numero"],
        "chave": chave,
        "comprovante": f"/api/v1/pix/comprovantes/{tx_id}",
    }), 201


@bp.route("/api/v1/pix/comprovantes/<int:tx_id>", methods=["GET"])
@bp.route("/pix/comprovantes/<int:tx_id>", methods=["GET"])
@login_obrigatorio(api=True)
def obter_comprovante(tx_id: int):
    db = get_db()
    _garantir_tabelas_pix(db)

    comp = db.execute("SELECT * FROM comprovantes_pix WHERE id = ?", (tx_id,)).fetchone()
    if not comp:
        return jsonify({"erro": "Comprovante não encontrado."}), 404

    # >>> CORREÇÃO TM-08 (IDOR/BOLA em Comprovantes): Exige que o usuário autenticado seja o dono do comprovante
    if comp["usuario_id"] != g.usuario["id"]:
        return jsonify({"erro": "Acesso negado ao comprovante de outro cliente."}), 403

    return jsonify({
        "id": comp["id"],
        "conta_origem": comp["conta_origem"],
        "conta_destino": comp["conta_destino"],
        "chave_destino": comp["chave_destino"],
        "valor": comp["valor"],
        "criado_em": comp["criado_em"],
    }), 200
