#!/usr/bin/env ruby
# frozen_string_literal: true

require 'cpe23'

module CveMonitor
  class CpeBuilder
    attr_accessor :skip

    def initialize
      @skip = false
    end

    def prompt(name, default = nil, *options)
      print "#{name}: "
      print "[#{default}] " unless default.nil?
      options.each do |option|
        print "| #{option} "
      end
      print '> '
      default = default&.downcase
      if @skip
        puts
        default
      else
        input = STDIN.gets
        if input.nil?
          @skip = true
          puts
          default
        else
          input.chomp!.downcase!
          input = default if input.empty? && !default.nil?
          input
        end
      end
    end

    def self.build
      instance = new
      cpe = Cpe23.new

      until %w[a o h].include? cpe.part
        input = instance.prompt('Part', 'Application', 'Operating System', 'Hardware')
        cpe.part = case input
                   when '', 'application', 'app' then 'a'
                   when 'operating system', 'os' then 'o'
                   when 'hardware', 'hw' then 'h'
                   else input
                   end
      end

      cpe.vendor = instance.prompt('Vendor') || '*'
      cpe.product = instance.prompt('Product') || '*'
      cpe.version = instance.prompt('Version', '*')
      cpe.update = instance.prompt('Update', '*')
      cpe.edition = '*' # deprecated
      cpe.language = instance.prompt('Language', '*')
      cpe.sw_edition = instance.prompt('Software Edition', '*')
      cpe.target_sw = instance.prompt('Target Software', '*')
      cpe.target_hw = instance.prompt('Target Hardware', '*')
      cpe.other = instance.prompt('Other', '*')

      cpe
    end
  end
end
