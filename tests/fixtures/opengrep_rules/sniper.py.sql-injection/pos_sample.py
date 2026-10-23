from flask import Flask, request
import os, subprocess, sqlite3, requests
app = Flask(__name__)

@app.route('/u')
def u():
    name = request.args.get('name')
    cur = sqlite3.connect('x').cursor()
    cur.execute("SELECT * FROM u WHERE n = '" + name + "'")
