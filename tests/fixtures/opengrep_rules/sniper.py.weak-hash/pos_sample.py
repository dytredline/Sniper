import hashlib

def h(pw):
    return hashlib.md5(pw.encode()).hexdigest()
