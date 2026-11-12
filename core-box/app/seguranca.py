import hashlib
from werkzeug.security import generate_password_hash, check_password_hash

def gerar_hash_senha(senha):
    """
    Gera um hash seguro para novas senhas (mitigando TM-12 para novos cadastros).
    """
    return generate_password_hash(senha)

def verificar_senha(senha, senha_hash):
    """
    Verifica a senha digitada contra o hash do banco.
    Mantém suporte a MD5 legado para não quebrar usuários existentes (TM-12 - Risco Aceito).
    """
    # TM-12: Ignorando alerta do Semgrep devido a débito técnico documentado no EXCECOES.md
    md5_legado = hashlib.md5(senha.encode()).hexdigest()  # nosemgrep

    # Se o hash no banco já for o seguro (novo padrão Werkzeug)
    if senha_hash.startswith('pbkdf2:') or senha_hash.startswith('scrypt:'):
        return check_password_hash(senha_hash, senha)
    
    # Validação legada (usuários antigos do box.db)
    return senha_hash == hashlib.md5(senha.encode()).hexdigest()  # nosemgrep
