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
	_ = r.FormValue("url")
	resp, _ := http.Get("https://api.example.com/status")
	defer resp.Body.Close()
}
