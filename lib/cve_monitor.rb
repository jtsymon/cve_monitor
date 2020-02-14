# frozen_string_literal: true

require 'cve_monitor/version'
require 'cve_monitor/lazy_hash'

# Add requires for other files you add to your project here, so
# you just need to require this one file in your bin file

module CveMonitor
  def self.parse_node(node)
    cpes = []
    node['children']&.each do |child|
      cpes += parse_node(child)
    end

    node['cpe_match']&.each do |cpe_match|
      # This is used for vulnerable configurations where this particular
      # component is not vulnerable.
      # TODO: Handle "operator" key to handle combinations properly.
      next if cpe_match['vulnerable'] == false

      cpe_str = cpe_match['cpe23Uri'] || cpe_match['cpe22Uri']
      # TODO: What about cpe_name array? Doesn't seem to be used.
      next if cpe_str.nil?

      cpes << Cpe23.parse(cpe_str)
      # TODO: handle versionStart/versionEnd
    end

    cpes
  end

  # Array intersection using comparison instead of hash.
  def self.intersect?(array1, array2)
    array1.each do |e1|
      return true if array2.any? { |e2| e1 == e2 }
    end
    false
  end
end
