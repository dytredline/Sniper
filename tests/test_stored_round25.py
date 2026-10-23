"""25. tur: diller arası ortak kalıcı depo (persistent store) modeli. Olumlu ve olumsuz örnekler.

Kural: depodan okunan veri yalnız istek verisinin o depoya yazıldığı kanıtlanırsa kaynaktır (kayıtlı veri).
Yazma kanıtı olan akışlar ikinci derece hedeflere de (SQL, komut, yol, yönlendirme) ulaşır; kanıtsız okumalar
eski davranışı korur (yalnız HTML/komut/eval/serileştirme/SSTI). Kimlik/sayı/tarih sütunları temiz sayılır.

* Ruby: bildirilmiş ilişki gezinmesi (``has_many :comments`` → ``rider.comments``), ilişki üzerinden yazım
  (``post.comments.create!``), kısmi görünüm yereli (``_post.html.erb`` ← ``render @posts``), flash/session deposu.
* Python: sütun düzeyinde kanıt (``Report(name=istek)`` → ``db.get(Report, id).name`` → SQL), Django ModelForm
  ``Meta.fields`` yazımı, kanıtta yazıldığı yer.
* Go: ``[]byte(x)`` dönüşümü içeriği taşır (kayıtlı yorum → ``w.Write``).
* C#: ``cmd.CommandText = "INSERT …"`` + ``Parameters.AddWithValue`` (yardımcı yöntem parametresi), şema önekli
  tablo, MERGE, bellek içi depo sınıfı koleksiyonu.
* Java: elle yazılmış depo sınıfı (``insert(Varlik v)``) → JSP EL; oturum özniteliği (``session.setAttribute``) → JSP EL.
* PHP: kayıtlı verinin başka tabloya kopyalanması (önizleme → yorumlar) ve yardımcı işlev parametresiyle yazım.
* JS: ORM yazımı (``Org.update({orgname: req.body.orgname})``) kanıtıyla ``res.send(kayit.orgname)``.
"""
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import project_analyzer  # noqa: E402
import taint_clike  # noqa: E402
import taint_flow as tf  # noqa: E402
import taint_goruby  # noqa: E402
import taint_js_ast  # noqa: E402
from tests.test_taint_js_ast import NODE_ENV  # noqa: E402


def _src(text):
    return textwrap.dedent(text).lstrip("\n")


def _flows(results):
    return {(path, f.sink_kind, f.line, f.source_label, f.source) for path, a in results.items() if a is not None
            for f in a.flows}


def _stored(results):
    return {(path, kind, line) for path, kind, line, label, _ in _flows(results) if label == "stored"}


class PolicyTests(unittest.TestCase):
    def test_write_evidence_marks(self):
        self.assertTrue(project_analyzer.stored_has_write_evidence("Report.name (kayıtlı veri)"))
        self.assertTrue(project_analyzer.stored_has_write_evidence(
            f"db.get().name ({tf.USER_WRITTEN_FIELD_MARK}: name)"))
        self.assertFalse(project_analyzer.stored_has_write_evidence("db.get()"))
        self.assertIn("sql", project_analyzer.STORED_EVIDENCED_FLOW_KINDS)
        self.assertNotIn("sql", project_analyzer.STORED_FLOW_KINDS)


class RubyStoredTests(unittest.TestCase):
    BASE = {
        "app/models/rider.rb": "class Rider < ActiveRecord::Base\n  def x\n  end\n  has_many :comments\nend\n",
        "app/models/comment.rb": "class Comment < ActiveRecord::Base\n  belongs_to :rider\nend\n",
        "app/controllers/riders_controller.rb": _src("""
            class RidersController < ApplicationController
              def index
                @riders = Rider.find(:all)
              end
            end
            """),
        "app/controllers/comments_controller.rb": _src("""
            class CommentsController < ApplicationController
              def create
                @comment = Comment.new(params[:comment])
                @rider.comments << @comment
              end
            end
            """),
    }

    def run_view(self, view, extra=None):
        files = dict(self.BASE)
        files.update(extra or {})
        files["app/views/riders/index.html.erb"] = _src(view)
        return taint_goruby.analyze_files(files, "ruby")

    def test_declared_association_from_record(self):
        res = self.run_view("""
            <% for rider in @riders %>
              <% for comment in rider.comments %>
                <%= raw comment.comment %>
              <% end %>
            <% end %>
            """)
        flows = [f for f in _flows(res) if f[3] == "stored"]
        self.assertEqual([(f[0], f[1], f[2]) for f in flows], [("app/views/riders/index.html.erb", "html", 3)])
        self.assertIn("Comment.comment (kayıtlı veri)", flows[0][4])

    def test_association_ids_and_dates_are_clean(self):
        res = self.run_view("""
            <% for rider in @riders %>
              <% rider.comments.each do |c| %>
                <%= raw c.rider_id %><%= raw c.created_at %>
              <% end %>
            <% end %>
            """)
        self.assertEqual(_stored(res), set())

    def test_association_without_write_is_clean(self):
        files = dict(self.BASE)
        files["app/controllers/comments_controller.rb"] = "class CommentsController < ApplicationController\nend\n"
        files["app/views/riders/index.html.erb"] = _src("""
            <% for rider in @riders %>
              <% for comment in rider.comments %><%= raw comment.comment %><% end %>
            <% end %>
            """)
        self.assertEqual(_stored(taint_goruby.analyze_files(files, "ruby")), set())

    def test_partial_local_and_association_write(self):
        files = {
            "app/models/post.rb": "class Post < ApplicationRecord\n  has_many :comments\nend\n",
            "app/models/comment.rb": "class Comment < ApplicationRecord\nend\n",
            "app/controllers/posts_controller.rb": _src("""
                class PostsController < ApplicationController
                  def create
                    @post = Post.new(post_params)
                    @post.save
                  end
                  def comment
                    @post = Post.find(params[:id])
                    @post.comments.create!(body: params[:body])
                  end
                  private
                  def post_params
                    params.require(:post).permit(:title, :body)
                  end
                end
                """),
            "app/views/posts/_post.html.erb": "<p><%= raw(auto_link(post.body, :sanitize => false)) %></p>\n",
            "app/views/posts/_comment.html.erb": "<p><%= raw comment.body %></p>\n",
            "app/views/posts/_tag.html.erb": "<p><%= raw tag.name %></p>\n",
        }
        stored = _stored(taint_goruby.analyze_files(files, "ruby"))
        self.assertIn(("app/views/posts/_post.html.erb", "html", 1), stored)
        self.assertIn(("app/views/posts/_comment.html.erb", "html", 1), stored)
        self.assertNotIn(("app/views/posts/_tag.html.erb", "html", 1), stored)  # Tag modeli yok

    def test_flash_and_session_store(self):
        files = {
            "app/controllers/s_controller.rb": _src("""
                class SController < ApplicationController
                  def create
                    flash[:error] = "User #{params[:u]} not found"
                    flash[:notice] = 'ok'
                    session[:theme] = params[:theme]
                    redirect_to root_path
                  end
                end
                """),
            "app/views/layouts/_m.html.erb": _src("""
                <% flash.each do |k, m| %><%= m.html_safe %><% end %>
                <%= flash[:notice].html_safe %>
                <%= raw session[:theme] %>
                <%= session[:theme] %>
                """),
        }
        stored = _stored(taint_goruby.analyze_files(files, "ruby"))
        self.assertEqual(stored, {("app/views/layouts/_m.html.erb", "html", 1),
                                  ("app/views/layouts/_m.html.erb", "html", 3)})

    def test_stored_second_order_sql_and_write_location(self):
        files = {
            "app/models/report.rb": "class Report < ApplicationRecord\nend\n",
            "app/controllers/reports_controller.rb": _src("""
                class ReportsController < ApplicationController
                  def create
                    Report.create!(name: params[:name])
                  end
                  def show
                    report = Report.find(params[:id])
                    ActiveRecord::Base.connection.exec_query("SELECT * FROM posts WHERE title = '#{report.name}'")
                  end
                end
                """),
        }
        res = taint_goruby.analyze_files(files, "ruby")
        flows = [f for f in res["app/controllers/reports_controller.rb"].flows if f.source_label == "stored"]
        self.assertEqual([(f.sink_kind, f.line) for f in flows], [("sql", 7)])
        self.assertEqual(flows[0].source_line, 3)  # yazıldığı satır kanıtta


class PythonStoredTests(unittest.TestCase):
    def analyze(self, src):
        return tf.analyze_python_files({"app/main.py": _src(src)})["app/main.py"]

    APP = """
        from fastapi import FastAPI, Request, Depends
        from sqlalchemy import text
        app = FastAPI()

        @app.post("/r")
        async def create(request: Request, db=Depends(get_db)):
            data = await request.json()
            report = Report(org_id=1, name=data.get("name"), count=int(data.get("n")))
            db.add(report)
            db.commit()

        @app.get("/r/{rid}")
        async def run(rid: int, db=Depends(get_db)):
            report = db.get(Report, rid)
            db.execute(text(f"SELECT * FROM posts WHERE status = '{report.name}'"))
            db.execute(text(f"SELECT * FROM posts WHERE id = {report.org_id}"))
            db.execute(text(f"SELECT * FROM posts WHERE t = '{report.title}'"))
        """

    def test_column_write_evidence_reaches_sql(self):
        flows = [f for f in self.analyze(self.APP).flows if f.source_label == "stored" and f.sink_kind == "sql"]
        marked = [f for f in flows if tf.USER_WRITTEN_FIELD_MARK in f.source]
        self.assertEqual([f.line for f in marked], [15])
        self.assertIn("yazıldığı yer: app/main.py:8", marked[0].source)
        # yazılmamış sütun (title) ve kimlik sütunu (org_id) kanıt taşımaz
        self.assertFalse(any(f.line in (16, 17) and tf.USER_WRITTEN_FIELD_MARK in f.source for f in flows))

    def test_project_reports_only_evidenced_second_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proj"
            (root / "app").mkdir(parents=True)
            (root / "app" / "main.py").write_text(_src(self.APP), encoding="utf-8")
            res = project_analyzer.analyze_project(str(root), allowed_roots=(Path(tmp),))
        rows = {(f.get("line"), f["title"]) for f in res["findings"] if "kayıtlı veri" in f["title"]}
        self.assertTrue(any(line == 15 and "SQL" in title for line, title in rows), rows)
        self.assertFalse(any(line in (16, 17) for line, _ in rows), rows)

    def test_django_model_form_fields_are_written(self):
        files = {
            "notes/forms.py": _src("""
                from django import forms
                from .models import Note
                class ReplyForm(forms.ModelForm):
                    class Meta:
                        model = Note
                        fields = ('content',)
                """),
            "notes/views.py": _src("""
                from django.db import connection
                from .forms import ReplyForm
                from .models import Note
                def reply(request):
                    form = ReplyForm(request.POST)
                    if form.is_valid():
                        form.save()
                def show(request, pk):
                    note = Note.objects.get(pk=pk)
                    connection.cursor().execute("SELECT * FROM t WHERE c = '%s'" % note.content)
                    connection.cursor().execute("SELECT * FROM t WHERE c = '%s'" % note.title)
                """),
        }
        flows = tf.analyze_python_files(files)["notes/views.py"].flows
        marked = [(f.sink_kind, f.line) for f in flows
                  if f.source_label == "stored" and tf.USER_WRITTEN_FIELD_MARK in f.source]
        self.assertEqual(marked, [("sql", 10)])
        self.assertTrue(any("yazıldığı yer: notes/views.py:5" in f.source for f in flows))


class GoStoredTests(unittest.TestCase):
    def test_byte_slice_conversion_carries_stored_and_request(self):
        src = _src("""
            package main

            import (
            	"database/sql"
            	"net/http"
            )

            var db *sql.DB

            func add(w http.ResponseWriter, r *http.Request) {
            	body := r.FormValue("b")
            	_, _ = db.Exec(`INSERT INTO comments(post_id,body) VALUES($1,$2)`, 1, body)
            }

            func show(w http.ResponseWriter, r *http.Request) {
            	var c string
            	var n int
            	db.QueryRow(`SELECT body FROM comments WHERE post_id=$1`, 1).Scan(&c)
            	db.QueryRow(`SELECT id FROM comments WHERE post_id=$1`, 1).Scan(&n)
            	w.Write([]byte("<div>" + c))
            	w.Write([]byte{byte(n)})
            }
            """)
        res = taint_goruby.analyze_files({"main.go": src}, "go")
        self.assertEqual(sorted((f.sink_kind, f.line, f.source_label) for f in res["main.go"].flows),
                         [("html", 20, "stored")])


class CSharpStoredTests(unittest.TestCase):
    SRC = """
        using Microsoft.AspNetCore.Mvc;
        public class CController : Controller {
            [HttpPost]
            public IActionResult Add(string body) { Store.AddComment(1, body); return Ok(); }
            public IActionResult Html() { var f = Store.GetBody(1); return Content("<b>" + f, "text/html"); }
            public IActionResult Other() { var f = Store.GetOther(1); return Content("<b>" + f, "text/html"); }
        }
        public static class Store {
            public static void AddComment(int uid, string body) { using var c = Conn(); using var cmd = c.CreateCommand(); cmd.CommandText = "INSERT INTO dbo.Comments (UserId,Body) VALUES (@uid,@body)"; cmd.Parameters.AddWithValue("@uid", uid); cmd.Parameters.AddWithValue("@body", body); cmd.ExecuteNonQuery(); }
            public static string GetBody(int id) { using var c = Conn(); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT Body FROM dbo.Comments WHERE UserId=@uid"; cmd.Parameters.AddWithValue("@uid", id); return cmd.ExecuteScalar()?.ToString() ?? ""; }
            public static string GetOther(int id) { using var c = Conn(); using var cmd = c.CreateCommand(); cmd.CommandText = "SELECT Name FROM dbo.Others WHERE Id=@id"; cmd.Parameters.AddWithValue("@id", id); return cmd.ExecuteScalar()?.ToString() ?? ""; }
        }
        """

    def test_command_text_helper_write_and_read(self):
        res = taint_clike.analyze_files({"C.cs": _src(self.SRC)})
        self.assertEqual(_stored(res), {("C.cs", "html", 5)})

    def test_merge_and_schema_prefix(self):
        project = taint_clike.Project
        self.assertEqual(project.write_table(project, "MERGE dbo.ReportFilters AS t USING x"), "reportfilters")
        self.assertEqual(project.write_table(project, "INSERT INTO [dbo].[Users] (a) VALUES (1)"), "users")
        self.assertIsNone(project.write_table(project, "SELECT updated_at FROM t"))

    def test_in_memory_repository_collection(self):
        files = {
            "Repo.cs": _src("""
                using System.Collections.Generic;
                public class CommentsRepository {
                    private List<Comment> Comments = new List<Comment>();
                    public void Save(Comment c) { Comments.Add(c); }
                    public List<Comment> All() { return Comments; }
                }
                public class Comment { public string Text { get; set; } public string Username { get; set; } }
                """),
            "C.cs": _src("""
                using Microsoft.AspNetCore.Mvc;
                public class CController : Controller {
                    private CommentsRepository repo;
                    [HttpPost]
                    public IActionResult Add(CommentForm form) {
                        Comment c = new Comment();
                        c.Text = form.Text;
                        c.Username = "Anonymous";
                        repo.Save(c);
                        return Ok();
                    }
                }
                """),
            "Views/C/Index.cshtml": _src("""
                @model List<Comment>
                @foreach (var item in Model) {
                    <p>@Html.Raw(item.Text)</p>
                    <b>@Html.Raw(item.Username)</b>
                }
                """),
        }
        stored = _stored(taint_clike.analyze_files(files))
        self.assertIn(("Views/C/Index.cshtml", "html", 3), stored)
        self.assertNotIn(("Views/C/Index.cshtml", "html", 4), stored)


class JavaStoredTests(unittest.TestCase):
    FILES = {
        "src/main/java/app/AdRepository.java": """
            package app;
            @Repository
            public class AdRepository {
                public void insert(Ad ad) { jdbc.update("INSERT INTO AD(TITLE) VALUES (?)", ad.getTitle()); }
                public List<Ad> findAll() { return jdbc.query("SELECT * FROM AD", MAPPER); }
            }
            """,
        "src/main/java/app/AdController.java": """
            package app;
            @Controller
            public class AdController {
                @Autowired
                private AdRepository adRepository;
                @RequestMapping("/")
                String home(Model model) {
                    model.addAttribute("ads", this.adRepository.findAll());
                    return "home";
                }
                @RequestMapping(value = "/new", method = RequestMethod.POST)
                String create(@RequestParam("title") String title, @RequestParam("name") String name, HttpSession session) {
                    Ad ad = new Ad();
                    ad.setTitle(title);
                    this.adRepository.insert(ad);
                    User user = new User();
                    user.setName(name);
                    user.setId(7);
                    session.setAttribute("sessionUser", user);
                    return "redirect:/";
                }
            }
            """,
        "src/main/webapp/WEB-INF/jsp/home.jsp": """
            <c:forEach items="${ads}" var="ad">
            <div>${ad.title}</div>
            <span>${ad.createDate}</span>
            </c:forEach>
            """,
        "src/main/webapp/WEB-INF/jsp/include/header.jsp": """
            <a>Hi ${sessionUser.name}</a>
            <a>${sessionUser.id}</a>
            """,
    }

    def test_repository_class_and_session_attribute(self):
        stored = _stored(taint_clike.analyze_files({k: _src(v) for k, v in self.FILES.items()}))
        self.assertEqual(stored, {("src/main/webapp/WEB-INF/jsp/home.jsp", "html", 2),
                                  ("src/main/webapp/WEB-INF/jsp/include/header.jsp", "html", 1)})


class PhpStoredTests(unittest.TestCase):
    FILES = {
        "inc/comments.php": """
            <?php
            class Comments {
               static function add_preview($text) {
                  $q = sprintf("INSERT INTO `comments_preview` (`id`, `text`) VALUES (NULL, '%s');", mysql_real_escape_string($text));
                  mysql_query($q);
               }
               static function publish($id) {
                  $res = mysql_query(sprintf("SELECT `text` FROM `comments_preview` WHERE `id` = '%d'", $id));
                  $p = mysql_fetch_assoc($res);
                  mysql_query(sprintf("INSERT INTO `comments` (`id`, `text`) VALUES (NULL, '%s');", mysql_real_escape_string($p['text'])));
               }
               static function all() {
                  $res = mysql_query("SELECT `text` FROM `comments`");
                  while ($row = mysql_fetch_assoc($res)) { $out[] = $row; }
                  return $out;
               }
            }
            """,
        "preview.php": """
            <?php
            require_once("inc/comments.php");
            Comments::add_preview($_POST['text']);
            Comments::publish($_POST['id']);
            """,
        "view.php": """
            <?php
            require_once("inc/comments.php");
            $comments = Comments::all();
            foreach ($comments as $c) { echo "<p>" . $c['text'] . "</p>"; }
            """,
    }

    def test_stored_copied_between_tables(self):
        stored = _stored(taint_clike.analyze_files({k: _src(v) for k, v in self.FILES.items()}))
        self.assertIn(("view.php", "html", 4), stored)

    def test_no_write_no_stored(self):
        files = {k: _src(v) for k, v in self.FILES.items() if k != "preview.php"}
        self.assertEqual(_stored(taint_clike.analyze_files(files)), set())


@unittest.skipIf(NODE_ENV is None, "node bulunamadı")
class JsStoredTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, NODE_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def flows(self, src):
        results = taint_js_ast.analyze_files({"app.js": _src(src)})
        self.assertIsNotNone(results)
        return [(f.sink_kind, f.line, f.source) for f in results["app.js"].flows if f.source_label == "stored"]

    def test_orm_write_evidence_res_send(self):
        flows = self.flows("""
            const express = require('express'); const app = express();
            const Org = require('./models').Org;
            app.get('/myorg', (req, res) => {
              Org.findOne({where: {owner: req.user.username}}).then((r) => {
                res.send(r.orgname);
                res.send(r.owner);
                res.send(r.createdAt);
              });
            });
            app.post('/upd', (req, res) => {
              Org.update({orgname: req.body.orgname, createdAt: req.body.t}, {where: {owner: 1}});
              res.send('ok');
            });
            """)
        self.assertEqual([(k, line) for k, line, _ in flows], [("html", 5)])
        self.assertIn("yazıldığı yer: app.js:11", flows[0][2])

    def test_mongo_update_filter_is_not_write(self):
        flows = self.flows("""
            const express = require('express'); const app = express();
            const User = require('./models').User;
            app.get('/u', async (req, res) => { const u = await User.findOne({}); res.send(u.name); });
            app.post('/u', (req, res) => { User.updateOne({name: req.body.name}, {$set: {seen: true}}); res.send('ok'); });
            """)
        self.assertEqual(flows, [])


if __name__ == "__main__":
    unittest.main()
