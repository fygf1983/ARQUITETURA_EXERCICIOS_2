# Atualização do Threat Model e Backlog de Segurança — Dia 02 (Core Box)

Este documento consolida a evolução das ameaças mapeadas no Dia 01 (STRIDE) e os novos achados introduzidos pelas ferramentas automatizadas da esteira DevSecOps no Dia 02.

## 1. Status das Ameaças Prioritárias do Dia 01 (Must-Fix)

| ID | Categoria STRIDE | Ameaça / Vulnerabilidade | Componente | Status Dia 02 | Evidência de Mitigação |
|---|---|---|---|---|---|
| **TM-03** | Elevation of Privilege / Tampering | **BOLA / IDOR** na transferência e consulta de contas de terceiros | `app/rotas_api.py` | ✅ Mitigado | Validação `conta.usuario_id == g.usuario_id` + teste automatizado no Pytest |
| **TM-07** | Information Disclosure | Modo Debug ativo e exposição de stack trace em exceções | `app/main.py` / `config.py` | ✅ Mitigado | `debug=False` forçado em produção e tratamento genérico de erros |
| **TM-12** | Information Disclosure | Hash de senha fraco / poucas iterações no PBKDF2 | `app/seguranca.py` | ✅ Mitigado | PBKDF2-HMAC-SHA256 elevado para 600.000 iterações |
| **TM-23** | Information Disclosure | Enumeração de CPFs cadastrados via mensagens distintas | `app/rotas_api.py` | ✅ Mitigado | Respostas unificadas em `/login`, `/abrir-conta` e `/recuperar` |
| **TM-29** | Tampering / Information Disclosure | SQL Injection em filtros e consultas diretas | Camada de Dados | ✅ Mitigado | Consultas parametrizadas validadas pelo Semgrep e Pytest |

---

## 2. Novos Achados Identificados na Esteira do Dia 02 (TM-33 a TM-37)

| ID | Origem (Etapa) | Categoria STRIDE | Descrição do Achado | Severidade | Tratamento no Dia 02 |
|---|---|---|---|---|---|
| **TM-33** | Etapa 02 (Semgrep) | Elevation of Privilege | Desserialização insegura com `yaml.load()` permitindo execução remota de código (RCE) | Crítica | ✅ **Corrigido:** Substituído por `yaml.safe_load()` em `app/rotas_api.py`. |
| **TM-34** | Etapa 04 (Trivy FS) | Tampering / DoS | Dependências Python desatualizadas com CVEs conhecidas (`Flask`, `Werkzeug`, `urllib3`, `requests`, `PyJWT`) | Alta | ✅ **Corrigido:** `requirements.txt` atualizado para versões seguras; 0 vulnerabilidades no Trivy FS. |
| **TM-35** | Etapa 02 / 06 (Docker) | Elevation of Privilege | Container rodando como `root` e sem `HEALTHCHECK` definido | Alta | ✅ **Corrigido:** Criado usuário `appuser` (UID 1000), `HEALTHCHECK` e `CMD` exec no `Dockerfile`. |
| **TM-36** | Etapa 06 (Trivy Image) | Elevation of Privilege | Vulnerabilidade `CVE-2025-47273` em `setuptools` reportada via metadado SBOM da imagem base | Alta | ✅ **Mitigado / Exceção (`EXC-05`):** Diretórios removidos no build e falso positivo de SBOM suprimido via `/tmp/.trivyignore`. |
| **TM-37** | Etapa 07 (OWASP ZAP) | Tampering / Info Disclosure | Ausência de cabeçalhos HTTP de segurança (`CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Permissions-Policy`, `COEP`) | Baixa / Média | 📋 **Backlog (`EXC-06`):** Registrado com risco aceito temporariamente (`WARN-NEW: 7`, `FAIL-NEW: 0`) para implementação via middleware/proxy reverso. |
