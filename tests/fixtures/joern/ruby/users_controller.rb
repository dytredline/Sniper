# Ruby on Rails kaynak/hedef modelleri: olumlu (EXPECT) ve olumsuz örnekler.
class UsersController < ApplicationController
  def show
    User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}") # EXPECT: sql
    User.where("name = ?", params[:name])
    User.where("name = '#{params[:name]}'") # EXPECT: sql
    system("ping -c 1 #{params[:host]}") # EXPECT: command
    system("ping", "-c", "1", "localhost")
    listing = `ls #{params[:dir]}` # EXPECT: command
    eval(params[:code]) # EXPECT: eval
    redirect_to params[:url] # EXPECT: redirect
    redirect_to root_path
    @bio = params[:bio].html_safe # EXPECT: xss
    @safe = "sabit".html_safe
    send_file params[:file] # EXPECT: path
    send_file Rails.root.join("public", "rapor.pdf")
  end
end
