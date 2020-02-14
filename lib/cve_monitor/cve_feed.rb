# frozen_string_literal: true

module CveMonitor
  class CveFeed
    def initialize(feed)
      @uri = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-#{feed}.json.gz"
    end

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

    def check(cpe_list)
      cves = URI.open(@uri) do |f|
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
        matching = cpe_list.match? cpes
        next if matching.empty?

        puts "https://nvd.nist.gov/vuln/detail/#{cve_id}", matching, "\n"
      end
    end
  end
end
