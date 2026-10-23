from flask import Flask, request
import os, subprocess, sqlite3, requests
app = Flask(__name__)

@app.route('/u')
def u():
    name = request.args.get('name')
    uid = int(request.args.get('id'))
    cur = sqlite3.connect('x').cursor()
    cur.execute('SELECT * FROM u WHERE n = ?', (name,))
    cur.execute('SELECT * FROM u WHERE id = %d' % uid)
