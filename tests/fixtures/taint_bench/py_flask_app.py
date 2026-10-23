import logging
import os
import re
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.route("/search")
def search():
    term = request.args.get("q", "")
    logger.info("search term: %s", term)  # EXPECT: LOGG-03
    logger.info("raw: " + request.args.get("q"))  # EXPECT: LOGG-03
    logger.info("count=%d", len(request.args))
    page = int(request.args.get("page", 1))
    logger.info("page " + str(page))
    logger.warning(  # EXPECT: LOGG-03
        "multi-line %s",
        request.args.get("q"),
    )
    logger.info("repr %r", term)
    logger.info("clean " + term.replace("\n", "").replace("\r", ""))
    db = sqlite3.connect("x.db")
    sql = "SELECT * FROM items WHERE name = '" + term + "'"
    db.execute(sql)  # EXPECT: SQL
    db.execute("SELECT * FROM items WHERE name = ?", (term,))
    db.execute("SELECT 1 FROM t WHERE a = " + "1")
    pattern = request.args.get("re")
    re.search(pattern, "text")  # EXPECT: DOS-REGEX
    re.search(re.escape(pattern), "text")
    os.system("echo " + term)  # EXPECT: CMD
    subprocess.run(["echo", term], check=False)
    return "ok"


@app.route("/item/<int:item_id>", methods=["DELETE"])
def delete_item(item_id):
    logger.info("deleted %s", item_id)
    return "", 204
