import jwt

def claims(tok, key):
    return jwt.decode(tok, key, algorithms=['HS256'])
