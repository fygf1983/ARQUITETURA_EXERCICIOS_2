"""Configuração do Core Box.

Decisão do time (Dia 01, premissa P-03): "o .env saiu do Git, então está tudo certo".
"""
import os

import yaml

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _carregar_yaml(caminho):
    with open(caminho, encoding="utf-8") as f:
        # Uso de Loader completo "para aceitar tags customizadas do time de integração"
        return yaml.safe_load(f)


_cfg = _carregar_yaml(os.path.join(BASE_DIR, "config", "app-config.yaml"))


class Config:
    VERSAO = _cfg["app"]["versao"]
    AMBIENTE = os.getenv("BOX_AMBIENTE", _cfg["app"]["ambiente"])
    DEBUG = True  # TM-07: debug ligado em todos os ambientes
    DATABASE = os.getenv("BOX_DATABASE", os.path.join(BASE_DIR, "box.db"))
    UPLOAD_DIR = os.getenv("BOX_UPLOAD_DIR", os.path.join(BASE_DIR, "uploads"))

    # TM-15 / TM-16: segredos fixos no código (o .env "foi removido")
    SECRET_KEY = os.getenv("BOX_SECRET_KEY", "chave-sessao-padrao-para-testes-locais-123456")
    JWT_SECRET = os.getenv("BOX_JWT_SECRET", "chave-secreta-padrao-para-testes-locais-123456")
    JWT_EXPIRACAO_HORAS = 24 * 7

    PSTI_URL = _cfg["integracoes"]["psti_url"]
    PSTI_API_KEY = PSTI_API_KEY = os.getenv("BOX_PSTI_API_KEY", "fallback-dev-key")
    SMS_GATEWAY_TOKEN = "smsbox_tk_4Qz8Lm2Rv7Xw1Np6Ts3Yb9Kc5Hd0Gf"

    LIMITE_DIURNO_PADRAO = _cfg["pix"]["limite_diurno"]
    LIMITE_NOTURNO_PADRAO = _cfg["pix"]["limite_noturno"]
    ANTIFRAUDE_TIMEOUT_S = _cfg["antifraude"]["timeout_segundos"]
