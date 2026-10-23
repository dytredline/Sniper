package main

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

func find(db *sql.DB, name string) {
	db.Query("SELECT * FROM users WHERE name = ?", name)
}
