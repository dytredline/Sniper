# Rails scope lambdası ve argümansız güçlü parametre yardımcısı.
class Report < ApplicationRecord
  scope :by_cols, ->(cols) { select("#{cols}") }
end

class ReportsController < ApplicationController
  def index
    @rows = Report.by_cols(report_fields) # EXPECT: sql
    @safe = Report.by_cols("id, name")
  end

  private

  def report_fields
    params.require(:fields).keys.join(",")
  end
end
