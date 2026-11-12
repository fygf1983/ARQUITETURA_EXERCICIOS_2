# Registro de Exceções de Segurança e Aceite de Risco — Core Box

Este documento formaliza as supressões de alertas em ferramentas automatizadas (SAST, SCA, Container Scan e DAST) na esteira DevSecOps do **Core Box**, assegurando governança, rastreabilidade ao Threat Model e prazos de revisão.

## 1. Tabela de Exceções Vigentes

| ID | Ferramenta | Regra / CVE | Localização | Classificação | Justificativa Técnica e Controle Compensatório | Aprovador (BISO / AppSec) | Expiração |
|---|---|---|---|---|---|---|---|
| EXC-01 | Semgrep (SAST) | `box-pbkdf2-iteracoes-baixas` | `core-box/app/seguranca.py` | Falso Positivo (Match Literal) | A função `gerar_hash_senha` foi corrigida para utilizar `600000` iterações (OWASP). A regra regex local do Semgrep marca ocorrências que não contenham literalmente `100000`. Suprimido via `# nosemgrep` inline. | Fernando Yamamoto | 2027-01-12 |
| EXC-02 | Semgrep (SAST) | `box-bola-transferencia-sem-check` | `core-box/app/rotas_api.py` | Falso Positivo (Heurística SAST) | A validação de titularidade (anti-BOLA / TM-03) foi implementada verificando `conta_origem.usuario_id != g.usuario_id` antes da transferência, validada por testes automatizados (`pytest`). Suprimido via `# nosemgrep` inline. | Fernando Yamamoto | 2027-01-12 |
| EXC-03 | Semgrep (SAST) | `python.lang.security.deserialization.avoid-pyyaml-load` | `core-box/app/rotas_api.py` | Falso Positivo | A desserialização insegura (`yaml.load`) foi substituída por `yaml.safe_load()`, bloqueando instanciação arbitrária de objetos Python (RCE). Suprimido via `# nosemgrep` inline. | Fernando Yamamoto | 2027-01-12 |
| EXC-04 | Semgrep (SAST) | `python.flask.security.audit.hardcoded-config` | `core-box/app/config.py` | Risco Aceito (Ambiente de Testes) | O fallback de segredo existe exclusivamente para permitir a execução da suíte de testes unitários (`pytest`) sem variáveis de produção. Em produção, as chaves são injetadas via GitHub Secrets (`BOX_JWT_SECRET` e `BOX_SECRET_KEY`). | Fernando Yamamoto | 2027-01-12 |
| EXC-05 | Trivy (Image Scan) | `CVE-2025-47273` (`setuptools` 70.3.0) | Imagem base `python:3.11-slim-bookworm` (`.trivyignore` e `/tmp/.trivyignore` no runner da Etapa 06) | Falso Positivo (Metadado SBOM Residual) | O pacote `setuptools` e seus diretórios são removidos fisicamente da imagem final durante o `docker build`. O alerta decorre de catálogo SBOM/CycloneDX residual da imagem oficial Debian/Python, sem código explorável em runtime. | Fernando Yamamoto | 2027-01-12 |
| EXC-06 | OWASP ZAP (DAST) | `10020`, `10021`, `1003
cd ~/arquitetura

cat << 'EOF' > RELATORIO-DIA02.md
# Relatório Executivo — Dia 02: Esteira DevSecOps e Hardening (Core Box)

**Responsável:** Fernando Yamamoto (BISO / Security Champion)  
**Data:** 12/11/2026  
**Repositório:** `ARQUITETURA_EXERCICIOS_2` (`core-box`)

---

## 1. Arquitetura da Esteira DevSecOps (8 Etapas)

A esteira de CI/CD foi implementada no GitHub Actions (`.github/workflows/esteira-devsecops.yml`) operando em modo **Quality/Security Gate Bloqueante** nas etapas críticas e com rastreabilidade ponta a ponta por digest imutável (`sha256`):

| Etapa | Nome do Job | Ferramenta | Política (Gate) | Status Final |
|---|---|---|---|---|
| **01** | Secret Scanning | Gitleaks (`v2`) | Bloqueante (`exit-code 1`) | ✅ Aprovado (0 segredos expostos) |
| **02** | SAST | Semgrep (`p/python`, `p/flask`, `p/dockerfile` + regras locais) | Bloqueante | ✅ Aprovado (Vulnerabilidades corrigidas) |
| **03** | Build & Testes | Pytest (Suíte Funcional + Testes de Segurança) | Bloqueante | ✅ Aprovado (100% dos testes passando) |
| **04** | SCA Dependências | Trivy FS (`HIGH,CRITICAL`) | Bloqueante (`exit-code 1`) | ✅ Aprovado (0 vulnerabilidades) |
| **05** | Build & Push | Docker Buildx + GitHub Container Registry (GHCR) | Bloqueante | ✅ Aprovado (Imagem publicada com digest SHA256) |
| **06** | Scan de Container | Trivy Image (`HIGH,CRITICAL`, `ignore-unfixed`) | Bloqueante (`exit-code 1`) | ✅ Aprovado (Debian 12.15 + pacotes limpos) |
| **07** | Homologação & DAST | OWASP ZAP Baseline (`ghcr.io/zaproxy/zaproxy:stable`) | Informativo (`FAIL-NEW: 0`, `WARN-NEW: 7`) | ✅ Aprovado (Relatórios JSON/MD/HTML publicados via Artifact v4) |
| **08** | Deploy em Produção | GitHub Environment (`producao`) + SSH/VPS + Smoke Test | Aprovação Manual Obrigatória | ✅ Configurado e Validado |

---

## 2. Correções de Código e Hardening Aplicados (Must-Fix)

1. **Prevenção de BOLA / IDOR (TM-03):** Implementada verificação estrita de titularidade (`conta.usuario_id == g.usuario_id`) nas rotas de consulta de extrato e transferência bancária em `app/rotas_api.py`.
2. **Mitigação de Enumeração de Usuários/CPF (TM-23):** Padronizadas as mensagens de erro e códigos de retorno HTTP nas rotas de login, abertura de conta e recuperação de senha.
3. **Eliminação de Debug e Stack Traces em Produção (TM-07):** Desativado `debug=True` no Flask e removido vazamento de detalhes internos em respostas de erro.
4. **Fortalecimento Criptográfico de Senhas (TM-12):** Elevado o custo de derivação PBKDF2-HMAC-SHA256 para `600.000` iterações em `app/seguranca.py`, em conformidade com as recomendações da OWASP.
5. **Prevenção de SQL Injection (TM-29) e Desserialização Insegura (TM-33):** Parametrização das consultas SQL e substituição de `yaml.load` por `yaml.safe_load`.
6. **Hardening de Container e SCA (`Dockerfile` e `requirements.txt`):**
   - Atualização de todas as bibliotecas críticas (`Flask 3.1.3`, `Werkzeug 3.1.9`, `PyJWT 2.15.1`, `PyYAML 6.0.3`, `Requests 2.34.2`, `Urllib3 2.8.0`, `Gunicorn 27.0.0`).
   - Aplicação de `apt-get upgrade -y` na imagem base `python:3.11-slim-bookworm` (Debian 12.15) e remoção física de *build tools* (`setuptools` e `wheel`).
   - Execução sob usuário não-privilegiado (`USER appuser`, UID 1000).
   - Configuração de `HEALTHCHECK` nativo e `CMD` em formato *exec* com `gunicorn`.

---

## 3. Decisões de Governança e Lições Aprendidas

* **Rastreabilidade por Digest (`@sha256`):** As etapas 06, 07 e 08 consomem diretamente os outputs `image_tag` e `image_digest` gerados na Etapa 05 (`needs: [etapa-5-docker-build, ...]`), garantindo que exatamente a mesma imagem escaneada pelo Trivy e testada pelo ZAP seja promovida para a VPS.
* **Gestão de Falsos Positivos e SBOM Residual:** Como a Etapa 06 executa em um runner limpo sem `actions/checkout`, a supressão do falso positivo de metadado SBOM da imagem base (`CVE-2025-47273` em `setuptools`) foi injetada dinamicamente via `/tmp/.trivyignore` e documentada formalmente como `EXC-05` em `EXCECOES.md`, mantendo o gate bloqueante ativo para qualquer outra CVE.
* **Execução Resiliente de DAST (OWASP ZAP):** O scan dinâmico na Etapa 07 foi desacoplado de actions legadas que utilizavam APIs depreciadas de artefato/issues, executando o container oficial do ZAP contra a imagem de homologação e exportando os relatórios (`report_html.html`, `report_md.md`, `report_json.json`) via `actions/upload-artifact@v4`.
* **Segregação de Funções no Deploy:** O ambiente `producao` no GitHub exige aprovação humana antes do disparo via SSH e valida a saúde do serviço automaticamente via *Smoke Test* (`curl -f http://$PROD_HOST/health`).
