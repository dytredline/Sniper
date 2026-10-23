"""Fonksiyonlar arası ölçüm: yardımcı modül (hedefler burada, kaynaklar py_ip_views.py'de)."""
import logging
import os
import pickle
import subprocess

import requests

logger = logging.getLogger(__name__)
ALLOWED_REPORTS = {"daily", "weekly"}


def run_report(name):
    subprocess.run(f"report.sh {name}", shell=True)  # EXPECT: CMD


def run_fixed(name):
    if name not in ALLOWED_REPORTS:
        raise ValueError("bilinmeyen rapor")
    subprocess.run(f"report.sh {name}", shell=True)


def process(value):
    cleaned = value.strip()
    return _convert(cleaned)


def _convert(value):
    return subprocess.call("convert " + value, shell=True)  # EXPECT: CMD


def find_user(conn, username):
    query = "SELECT * FROM users WHERE name = '%s'" % username
    return conn.execute(query)  # EXPECT: SQL


def find_user_safe(conn, username):
    return conn.execute("SELECT * FROM users WHERE name = ?", (username,))


def normalize(value):
    return value.strip().lower()


def to_int(value):
    return int(value)


def current_query():
    from flask import request
    return request.args.get("q", "")


def audit(message):
    logger.info("audit: %s", message)  # EXPECT: LOGG-03


class Storage:
    def __init__(self, base):
        self.base = base

    def read(self, name):
        with open(os.path.join(self.base, name)) as handle:  # EXPECT: PATH
            return handle.read()

    def read_safe(self, name):
        with open(os.path.join(self.base, os.path.basename(name))) as handle:
            return handle.read()


def fetch(url):
    return requests.get(url, timeout=5)  # EXPECT: SSRF


def fetch_internal(path):
    return requests.get(f"https://api.internal.example/{path}", timeout=5)


def load_state(blob):
    return pickle.loads(blob)  # EXPECT: DESER
