import hashlib

def h(pw, data):
    etag = hashlib.md5(data, usedforsecurity=False).hexdigest()
    return hashlib.sha256(pw.encode()).hexdigest(), etag
