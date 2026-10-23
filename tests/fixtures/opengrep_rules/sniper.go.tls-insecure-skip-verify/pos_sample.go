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

func cfg() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}
