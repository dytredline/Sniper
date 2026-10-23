from flask import request
import sqlite3


def run_query(q):
    # Dosya içi fonksiyonlar arası akış: kaynak başka fonksiyonda, sink burada.
    sqlite3.connect('x').cursor().execute(q)


def handler():
    name = request.args.get('n')
    run_query("SELECT * FROM t WHERE n='" + name + "'")
