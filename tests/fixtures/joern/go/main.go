package main

// Go (net/http) kaynak/hedef modelleri: olumlu (EXPECT) ve olumsuz örnekler.
import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"strconv"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	db.Query("SELECT * FROM users WHERE id = '" + id + "'") // EXPECT: sql
	db.Query("SELECT * FROM users WHERE id = ?", id)
	name := r.FormValue("name")
	exec.Command("sh", "-c", "echo "+name).Run() // EXPECT: command
	exec.Command("echo", "sabit").Run()
	n, _ := strconv.Atoi(r.FormValue("n"))
	db.Exec(fmt.Sprintf("DELETE FROM t WHERE id = %d", n))
	os.Open(r.FormValue("file")) // EXPECT: path
	http.Redirect(w, r, r.FormValue("next"), http.StatusFound) // EXPECT: redirect
	page := template.HTML(r.FormValue("bio")) // EXPECT: xss
	fmt.Fprintf(w, "%s", template.HTMLEscapeString(name))
	fmt.Fprintf(w, "%s", r.URL.Path) // EXPECT: xss
	_ = page
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe("127.0.0.1:8080", nil)
}
