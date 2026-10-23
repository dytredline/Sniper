from flask import Flask, request
import os, subprocess, sqlite3, requests
app = Flask(__name__)

@app.route('/p')
def p():
    host = request.args.get('host')
    subprocess.run(['ping', '-c1', host])
    os.system('uptime')
