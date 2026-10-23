class JobsController < ApplicationController
  def run
    public_send("dangerous", params[:command])
  end

  def dangerous(value)
    system(value)
  end
end
