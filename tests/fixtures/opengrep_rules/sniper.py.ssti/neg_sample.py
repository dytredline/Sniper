from flask import Flask, request
import os, subprocess, sqlite3, requests
app = Flask(__name__)

from flask import render_template_string
@app.route('/hi')
def hi():
    return render_template_string('Merhaba {{ n }}', n=request.args.get('n'))
