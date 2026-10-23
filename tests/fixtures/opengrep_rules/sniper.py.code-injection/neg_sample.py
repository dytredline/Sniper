from flask import Flask, request
import os, subprocess, sqlite3, requests
app = Flask(__name__)

import ast
@app.route('/c')
def c():
    expr = request.form['expr']
    return str(ast.literal_eval(expr)) + str(eval('1+1'))
