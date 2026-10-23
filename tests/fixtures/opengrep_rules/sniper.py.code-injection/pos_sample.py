from flask import Flask, request
import os, subprocess, sqlite3, requests
app = Flask(__name__)

@app.route('/c')
def c():
    expr = request.form['expr']
    return str(eval(expr))
