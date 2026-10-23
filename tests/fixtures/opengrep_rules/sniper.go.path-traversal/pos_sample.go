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

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	data, _ := os.ReadFile("/srv/files/" + name)
	w.Write(data)
}
