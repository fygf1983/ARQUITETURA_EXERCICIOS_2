# Core Box — imagem de produção corrigida (hardening aplicado)
FROM python:3.11-slim-bookworm

# Aplica patches de segurança do SO e limpa o cache do apt
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Cria um usuário não-root por segurança e o diretório da app
RUN useradd -u 1000 appuser && mkdir /app && chown appuser:appuser /app

WORKDIR /app

# Atualiza pip e remove setuptools/wheel antigos do ensurepip para evitar CVEs de build tools
RUN pip install --no-cache-dir --upgrade pip && \
    rm -rf /usr/local/lib/python3.11/ensurepip/_bundled/setuptools* /usr/local/lib/python3.11/ensurepip/_bundled/wheel*

# Copia seletivamente os requisitos e instala as dependências sem utilitários extras
COPY --chown=appuser:appuser requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip uninstall -y setuptools wheel || true && find /usr/local -name "*sbom*" -delete

# Copia o restante do código da aplicação
COPY --chown=appuser:appuser . .

# Define o usuário restrito (não-root) para a execução
USER appuser

ENV BOX_AMBIENTE=producao
EXPOSE 8000

# Healthcheck para monitoramento de saúde do container
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# CMD em formato exec (vetor JSON) para propagação correta de sinais do SO
CMD ["gunicorn", "-b", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "wsgi:app"]
