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

func run(arg string) {
	exec.Command("ls", arg).Run()
	exec.Command("sh", "-c", "uptime").Run()
}
