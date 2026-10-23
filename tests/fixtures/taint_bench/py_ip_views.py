"""Fonksiyonlar arası ölçüm: Flask görünümleri (kaynaklar burada)."""
import os
import sqlite3

from flask import Flask, redirect, request

import py_ip_helpers as helpers
from py_ip_helpers import Storage, fetch, fetch_internal, find_user, find_user_safe, load_state, normalize, run_fixed, run_report, to_int

app = Flask(__name__)
ALLOWED_NEXT = {"/", "/home"}


@app.route("/report")
def report():
    run_report(normalize(request.args.get("name", "")))
    run_fixed(request.args.get("name", ""))
    return "ok"


@app.route("/convert")
def convert():
    helpers.process(request.args["p"])
    return "ok"


@app.route("/user")
def user():
    conn = sqlite3.connect("app.db")
    find_user(conn, request.args["u"])
    find_user_safe(conn, request.args["u"])
    return "ok"


@app.route("/count")
def count():
    helpers.run_report(to_int(request.args.get("n", "0")))
    return "ok"


@app.route("/search")
def search():
    term = helpers.current_query()
    os.system("grep -r " + term + " /srv/docs")  # EXPECT: CMD
    return "ok"


@app.route("/file")
def read_file():
    store = Storage("/srv/files")
    data = store.read(request.args["f"])
    safe = store.read_safe(request.args["f"])
    return data + safe


@app.route("/proxy")
def proxy():
    target = request.args.get("url")
    fetch(target)
    fetch_internal(request.args.get("path"))
    return "ok"


@app.route("/state", methods=["POST"])
def state():
    load_state(request.get_data())
    return "ok"


@app.route("/audit", methods=["POST"])
def audit_view():
    helpers.audit(request.form["note"])
    helpers.audit("sabit mesaj")
    return "ok"


@app.route("/next")
def go_next():
    target = request.args.get("next", "/")
    if target not in ALLOWED_NEXT:
        return redirect("/")
    return redirect(target)


@app.route("/next-unsafe")
def go_next_unsafe():
    return redirect(request.args.get("next", "/"))  # EXPECT: REDIRECT


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    if not name.isalnum():
        return "geçersiz", 400
    return f"<h1>Merhaba {name}</h1>"


@app.route("/hello-unsafe")
def hello_unsafe():
    name = request.args.get("name", "")
    return f"<h1>Merhaba {name}</h1>"  # EXPECT: XSS
