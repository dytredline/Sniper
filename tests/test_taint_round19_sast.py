"""19. tur SAST kolu: genel çatı kalıpları (C# satır içi ara katman, Sinatra, Hanami, Roda/Sequel, Go yardımcı yapı ve
adlandırılmış sonuçlar, Symfony/CodeIgniter/Slim/Laravel rota kapanışları) ve kesinlik (sabit tabanlı yönlendirme,
urlencode yol arındırıcısı, Sinatra yol yardımcıları)."""
from __future__ import annotations

from pathlib import Path
import sys
import textwrap
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import taint_clike  # noqa: E402
import taint_goruby  # noqa: E402


def _d(files: dict[str, str]) -> dict[str, str]:
    return {k: textwrap.dedent(v).lstrip("\n") for k, v in files.items()}


def clike(files: dict[str, str]) -> list[tuple]:
    res = taint_clike.analyze_files(_d(files), {})
    return sorted((f.file, f.sink_kind, f.line) for a in res.values() for f in a.flows if f.source_label == "request")


def ruby(files: dict[str, str]) -> list[tuple]:
    res = taint_goruby.analyze_files(_d(files), "ruby")
    return sorted((f.file, f.sink_kind, f.line) for a in res.values() for f in a.flows if f.source_label == "request")


def go(files: dict[str, str]) -> list[tuple]:
    res = taint_goruby.analyze_files(_d(files), "go")
    return sorted((f.file, f.sink_kind, f.line) for a in res.values() for f in a.flows if f.source_label == "request")


class CSharpMiddlewareTests(unittest.TestCase):
    def test_inline_middleware_lambda_is_endpoint(self):
        got = clike({"Startup.cs": """
            public class Startup {
                public void Configure(IApplicationBuilder app) {
                    app.Run(async (context) => {
                        string cmd = context.Request.Query["cmd"].ToString();
                        var p = new Process();
                        p.StartInfo.Arguments = $"-c \\"{cmd}\\"";
                        string q = context.Request.Query["q"].ToString();
                        await context.Response.WriteAsync($"<h1>{q}</h1>");
                        context.Response.Redirect(context.Request.Query["url"]);
                    });
                    Task.Run(() => DoWork());
                }
            }
        """})
        self.assertEqual(got, [("Startup.cs", "command", 6), ("Startup.cs", "html", 8), ("Startup.cs", "redirect", 9)])

    def test_argument_list_add(self):
        got = clike({"P.cs": """
            var app = WebApplication.Create(args);
            app.MapGet("/e", (HttpRequest req) => { var f = req.Query["f"].ToString(); var psi = new ProcessStartInfo("/bin/sh"); psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("printf " + f); return Results.Text("x"); });
            app.MapGet("/s", () => { var psi = new ProcessStartInfo("git"); psi.ArgumentList.Add("status"); return Results.Text("x"); });
        """})
        self.assertEqual(got, [("P.cs", "command", 2)])


class SinatraTests(unittest.TestCase):
    APP = """
        require 'sinatra'
        require 'nokogiri'
        get '/search' do
          query = params['query'] || ''
          "<h1>Results for: #{query}</h1>"
        end
        get '/json' do
          content_type :json
          "<b>#{params[:q]}</b>"
        end
        get '/go' do
          redirect params['url']
        end
        get '/home' do
          redirect '/home'
        end
        post '/q/:id' do
          redirect url("/queues/#{params[:id]}")
        end
        post '/xml' do
          doc = Nokogiri::XML(request.body.read) do |config|
            config.noent
          end
          Nokogiri::XML(request.body.read)
          'ok'
        end
        get '/reflect' do
          @stuff = params[:stuff]
          erb :reflected
        end
        get '/other' do
          @title = 'sabit'
          erb :reflected
        end
    """

    def test_route_return_redirect_xxe_and_unescaped_erb(self):
        got = ruby({"app.rb": self.APP, "views/reflected.erb": "<div><%= @stuff %></div>\n<p><%= @title %></p>\n"})
        self.assertEqual(got, [("app.rb", "html", 5), ("app.rb", "redirect", 12), ("app.rb", "xxe", 21),
                               ("views/reflected.erb", "html", 1)])

    def test_escape_html_setting_disables_erb_rule(self):
        app = "set :erb, :escape_html => true\n" + textwrap.dedent(self.APP)
        got = ruby({"app.rb": app, "views/reflected.erb": "<div><%= @stuff %></div>\n"})
        self.assertNotIn(("views/reflected.erb", "html", 1), got)

    def test_rails_erb_still_escaped(self):
        got = ruby({
            "app/controllers/pages_controller.rb": "class PagesController < ApplicationController\n"
                                                   "  def show\n    @q = params[:q]\n  end\nend\n",
            "app/views/pages/show.html.erb": "<p><%= @q %></p>\n",
        })
        self.assertEqual(got, [])


class RailsAssociationTests(unittest.TestCase):
    def test_association_records_and_for_loop_carry_stored_data(self):
        base = {
            "app/models/comment.rb": "class Comment < ActiveRecord::Base\n  belongs_to :rider\nend\n",
            "app/models/rider.rb": "class Rider < ActiveRecord::Base\n  has_many :comments\nend\n",
            "app/controllers/comments_controller.rb": "class CommentsController < ApplicationController\n  def create\n"
                                                      "    @comment = Comment.new(params[:comment])\n    @comment.save\n"
                                                      "  end\nend\n",
            "app/controllers/riders_controller.rb": "class RidersController < ApplicationController\n  def index\n"
                                                    "    @riders = Rider.find(:all)\n  end\nend\n",
            "app/views/riders/index.html.erb": "<% for rider in @riders %>\n<% for comment in rider.comments %>\n"
                                               "<%= raw comment.comment %>\n<%= comment.comment %>\n<%= raw rider.name %>\n"
                                               "<% end %>\n<% end %>\n",
        }
        res = taint_goruby.analyze_files(base, "ruby")
        got = sorted((f.file, f.sink_kind, f.line, f.source_label) for a in res.values() for f in a.flows)
        self.assertEqual(got, [("app/views/riders/index.html.erb", "html", 3, "stored")])


class HanamiRodaTests(unittest.TestCase):
    def test_hanami_action_and_sequel(self):
        got = ruby({"app/actions/books/show.rb": """
            module Bookshelf
              module Actions
                module Books
                  class Show < Bookshelf::Action
                    def handle(request, response)
                      id = request.params[:id]
                      rows = DB.fetch("SELECT * FROM books WHERE id = #{id}").all
                      safe = DB.fetch("SELECT * FROM books WHERE id = ?", id).all
                      response.redirect_to request.params[:next]
                    end
                  end
                end
              end
            end
        """})
        self.assertEqual(got, [("app/actions/books/show.rb", "redirect", 9), ("app/actions/books/show.rb", "sql", 7)])

    def test_roda_sequel_lit(self):
        got = ruby({"app.rb": """
            require 'roda'
            class App < Roda
              route do |r|
                r.get "s" do
                  DB[:t].where(Sequel.lit("a = '#{r.params['z']}'")).all
                end
              end
            end
        """})
        self.assertEqual(got, [("app.rb", "sql", 5)])


class GoHelperTests(unittest.TestCase):
    def test_request_in_helper_struct_and_named_results(self):
        got = go({"main.go": """
            package main
            import ("net/http"; "os/exec")
            type helper struct {
            	w http.ResponseWriter
            	r *http.Request
            }
            func (h helper) Param(n string) (v string, ok bool) {
            	q := h.r.URL.Query()
            	v = q.Get(n)
            	return
            }
            func (h helper) Fixed() (v string) {
            	v = "date"
            	return
            }
            func run(w http.ResponseWriter, r *http.Request) {
            	h := helper{w, r}
            	f, _ := h.Param("format")
            	exec.Command("sh", "-c", "date "+f).Output()
            	exec.Command("sh", "-c", h.Fixed()).Output()
            }
        """})
        self.assertEqual(got, [("main.go", "command", 19)])


class PhpFrameworkTests(unittest.TestCase):
    def test_symfony_doctrine_and_redirect(self):
        got = clike({"src/Controller/ApiController.php": """
            <?php
            namespace App\\Controller;
            use Symfony\\Component\\HttpFoundation\\Request;
            class ApiController extends AbstractController {
                public function search(Request $request) {
                    $q = $request->query->get('q');
                    $this->conn->executeQuery("SELECT * FROM t WHERE a = '" . $q . "'");
                    $this->conn->executeQuery("SELECT * FROM t WHERE a = ?", [$q]);
                    $this->em->createQuery("SELECT u FROM U u WHERE u.n = '" . $q . "'");
                    return $this->redirect($request->query->get('u'));
                }
                public function home() { return $this->redirect('/home'); }
            }
        """})
        self.assertEqual(got, [("src/Controller/ApiController.php", "redirect", 10),
                               ("src/Controller/ApiController.php", "sql", 7),
                               ("src/Controller/ApiController.php", "sql", 9)])

    def test_codeigniter_3_and_4(self):
        got = clike({
            "app/Controllers/News.php": """
                <?php
                namespace App\\Controllers;
                class News extends BaseController {
                    public function view() {
                        $slug = $this->request->getGet('slug');
                        $db->query("SELECT * FROM news WHERE slug = '" . $slug . "'");
                    }
                }
            """,
            "application/controllers/Old.php": """
                <?php
                class Old extends CI_Controller {
                    public function index() {
                        $this->db->query("SELECT * FROM t WHERE id = " . $this->input->get('id'));
                    }
                }
            """,
        })
        self.assertEqual(got, [("app/Controllers/News.php", "sql", 6), ("application/controllers/Old.php", "sql", 4)])

    def test_route_closures_slim_and_laravel(self):
        got = clike({"routes.php": """
            <?php
            $app->get('/hello', function (Request $request, Response $response, $args) {
                $name = $request->getQueryParams()['name'];
                $response->getBody()->write("<h1>Hello " . $name . "</h1>");
                return $response;
            });
            $app->get('/u/{id}', function (Request $request, Response $response, array $args) {
                $pdo->query("SELECT * FROM u WHERE id = " . $args['id']);
                return $response;
            });
            Route::get('/x', function (Request $r) { return DB::select("SELECT * FROM a WHERE b = " . $r->input('b')); });
            $stream->write($name);
        """})
        self.assertEqual(got, [("routes.php", "html", 4), ("routes.php", "sql", 8), ("routes.php", "sql", 11)])

    def test_fixed_base_redirect_and_urlencode_path(self):
        got = clike({"a.php": """
            <?php
            http_redirect(Pictures::$VIEW_PIC_URL . "?picid=" . $_POST['picid']);
            header("Location: " . $_GET['u']);
            $r = file_get_contents(__DIR__ . '/sim.php?prompt=' . urlencode($_POST['m']));
            include($_GET['p']);
        """})
        self.assertEqual(got, [("a.php", "path", 5), ("a.php", "redirect", 3)])


if __name__ == "__main__":
    unittest.main()
