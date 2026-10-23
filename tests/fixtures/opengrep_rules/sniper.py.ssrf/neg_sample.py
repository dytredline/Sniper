from flask import Flask, request
import os, subprocess, sqlite3, requests
app = Flask(__name__)

@app.route('/fetch')
def fetch():
    q = request.args.get('q')
    return requests.get('https://api.example.com/search', params={'q': q}).text
