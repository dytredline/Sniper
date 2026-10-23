from flask import Flask, request
import os, subprocess, sqlite3, requests
app = Flask(__name__)

@app.route('/f')
def f():
    name = os.path.basename(request.args.get('file'))
    with open(os.path.join('/srv/files', name)) as fh:
        return fh.read()
