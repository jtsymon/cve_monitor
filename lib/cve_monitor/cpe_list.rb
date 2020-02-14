# frozen_string_literal: true

module CveMonitor
  class CpeList
    attr_reader :cpes

    def initialize(path)
      @path = path
      @cpes = if File.exist?(path)
                File.open(path).map do |line|
                  Cpe23.parse(line)
                end
              else
                []
              end
    end

    def add!(cpes)
      @cpes += ensure_cpes(cpes)
    end

    def remove!(cpes)
      ensure_cpes(cpes).each do |cpe|
        @cpes.reject! { |e| e == cpe }
      end
    end

    def save!
      File.open(@path, 'w') do |file|
        @cpes.each do |cpe|
          file.write("#{cpe.to_str}\n")
        end
      end
    end

    def match?(cpes)
      cpes.select do |cpe|
        @cpes.any? { |e| e == cpe }
      end
    end

    def to_s
      @cpes.map(&:to_s).join("\n")
    end

    private

    def ensure_cpes(arr)
      arr.map { |elem| ensure_cpe(elem) }
    end

    def ensure_cpe(obj)
      case obj
      when Cpe23 then obj
      when String then Cpe23.parse(obj)
      else raise 'Arguments must be CPEs'
      end
    end
  end
end
