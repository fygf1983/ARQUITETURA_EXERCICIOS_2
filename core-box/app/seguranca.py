import hashlib
from werkzeug.security import generate_password_hash, check_password_hash

def hash_senha(senha: str) -> str:
    """
    Gera um hash seguro para senhas (mitigando TM-12 com PBKDF2/Scrypt).
    """
    return generate_password_hash(senha)

# Alias caso algum outro módulo chame pelo nome alternativo
gerar_hash_senha = hash_senha

def verificar_senha(senha: str, senha_hash: str) -> bool:
    """
    Verifica a senha digitada contra o hash do banco.
    Suporta hashes seguros do Werkzeug e mantém fallback para MD5 legado.
    """
    if not senha_hash:
        return False

    # Se o hash no banco for do Werkzeug (pbkdf2 ou scrypt)
    if senha_hash.startswith(("pbkdf2:", "scrypt:")):
        return check_password_hash(senha_hash, senha)

    # Fallback para senhas legadas em MD5 (TM-12 documentado no EXCECOES.md)
    md5_legado = hashlib.md5(senha.encode()).hexdigest()  # nosemgrep
    if senha_hash.startswith("md5$"):
        return check_password_hash(senha_hash, md5_legado)  # nosemgrep

    return senha_hash == md5_legado  # nosemgrep
