from passlib.context import CryptContext

pwd_context = CryptContext(schemes="bcrypt",deprecated="auto")

def pwd_hash(password:str)->str:
    return pwd_context.hash(password)

def verify_pass(password:str,hash_password:str)->str:
    return pwd_context.verify(password,hash_password)

