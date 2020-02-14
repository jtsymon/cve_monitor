# frozen_string_literal: true

require 'cve_monitor/version'
require 'cve_monitor/lazy_hash'

# Add requires for other files you add to your project here, so
# you just need to require this one file in your bin file

module CveMonitor
  def parse_node(node)
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
  def intersect?(array1, array2)
    array1.each do |e1|
      return true if array2.any? { |e2| e1 == e2 }
    end
    false
  end

  def check(feed)
    uri = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-#{feed}.json.gz"
    cves = URI.open(uri) do |f|
      begin
        gz = Zlib::GzipReader.new(f)
        JSON.parse(gz.read)
      ensure
        gz&.close
      end
    end
    cves['CVE_Items']&.each do |item|
      cve = item['cve']
      cve_id = cve.walk('CVE_data_meta', 'ID')
      cpes = item.walk('configurations', 'nodes')&.flat_map do |node|
        parse_node(node)
      end
      matching = cpes.select do |cpe|
        @cpes.any? { |e| e == cpe }
      end
      next if matching.empty?

      puts "https://nvd.nist.gov/vuln/detail/#{cve_id}", matching, "\n"
    end
  end
end
