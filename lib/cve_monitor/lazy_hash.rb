# frozen_string_literal: true

class Hash
  def walk(*keys)
    val = self
    keys.each do |key|
      val = val[key]
      break if val.nil?
    end
    val
  end
end
