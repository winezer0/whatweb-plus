# Copyright 2009 to 2020 Andrew Horton and Brendan Coles
#
# This file is part of WhatWeb.
#
# WhatWeb is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# at your option) any later version.
#
# WhatWeb is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with WhatWeb.  If not, see <http://www.gnu.org/licenses/>.

module WhatWeb
  class Scan
    def initialize(urls, input_file: nil, url_prefix: nil, url_suffix: nil, url_pattern: nil, max_threads: 25)
      urls = [urls] if urls.is_a?(String)

      @targets = make_target_list(
        urls,
        input_file: input_file,
        url_prefix: url_prefix,
        url_suffix: url_suffix,
        url_pattern: url_pattern
      )

      error('No targets selected') if @targets.empty?

      @max_threads = max_threads.to_i || 25
      $TARGET_QUEUE = Queue.new # workers consume from this
    end

    def scan
      Thread.abort_on_exception = true if $WWDEBUG

      workers = (1..@max_threads).map do
        Thread.new do
          # keep reading in root tasks until a nil is received
          loop do
            target = $TARGET_QUEUE.pop
            Thread.exit unless target

            # keep processing until there are no more redirects or the limit is hit
            # while target
            begin
              target.open
            rescue => e
              error("ERROR Opening: #{target} - #{e}")
              target = nil # break target loop
              next
            end

            yield target
          end
        end
      end

      # initialize target_queue
      @targets.each do |url|
          target = prepare_target(url)
          next unless target
              $TARGET_QUEUE << target
      end

      # exit

      loop do
        # this might miss redirects from final targets

        # more defensive than comparing against max_threads
        alive = workers.map { |worker| worker if worker.alive? }.compact.length
        break if alive == $TARGET_QUEUE.num_waiting && $TARGET_QUEUE.empty?
      end

      # Shut down workers, logging, and plugins
      (1..@max_threads).each { $TARGET_QUEUE << nil }
      workers.each(&:join)
    end

    # for use by Plugins
    def scan_from_plugin(target: nil)
      raise 'No target' unless target

      begin
        target.open
      rescue => e
        error("ERROR Opening: #{target} - #{e}")
      end
      target
    end

    def add_target(url, redirect_counter = 0)  #add_target 最终的添加目标URL的函数2 
      # TODO: REVIEW: should this use prepare_target?
      if (not $URLARRAY.include?(url))  ##判断是否存在重复URL
          $URLARRAY << url
          target = Target.new(url, redirect_counter)
          unless target
            error("Add Target Failed - #{url}")
            return
          end
          $TARGET_QUEUE << target
      end
    end

    private

    # try to make a new Target object, may return nil
    def prepare_target(url)  #prepare_target 最终的添加目标URL的函数1 
      if (not $URLARRAY.include?(url))
        $URLARRAY << url
        Target.new(url)
      end
      rescue => e
        error("Prepare Target Failed - #{e}")
        nil
    end

    #
    # Make Target List
    #
    # Make a list of targets from a list of URLs and/or input file
    #
    def make_target_list(urls, opts = {})
      url_list = []

      # parse URLs
      if urls.is_a?(Array)
        urls.flatten.reject { |u| u.nil? }.map { |u| u.strip }.reject { |u| u.eql?('') }.each do |url|
          url_list << url
        end
      end

      # parse input file
      # read each line as a url, skipping lines that begin with a #
      inputfile = opts[:input_file] || nil
      if !inputfile.nil? && File.exist?(inputfile)
        pp "loading input file: #{inputfile}" if $verbose > 2
        File.open(inputfile).readlines.each(&:strip!).reject { |line| line.start_with?('#') || line.eql?('') }.each do |line|
          url_list << line
        end
      end

      return [] if url_list.empty?

      # TODO: refactor this
      ip_range = url_list.map do |x|
        range = nil
        # Parse IP ranges
        if x =~ %r{^[0-9\.\-\/]+$} && x !~ %r{^[\d\.]+$}
          begin
            # CIDR notation
            if x =~ %r{\d+\.\d+\.\d+\.\d+/\d+$}
              range = IPAddr.new(x).to_range.map(&:to_s)
            # x.x.x.x-x
            elsif x =~ %r{^(\d+\.\d+\.\d+\.\d+)-(\d+)$}
              start_ip = IPAddr.new(Regexp.last_match(1), Socket::AF_INET)
              end_ip   = IPAddr.new("#{start_ip.to_s.split('.')[0..2].join('.')}.#{Regexp.last_match(2)}", Socket::AF_INET)
              range = (start_ip..end_ip).map(&:to_s)
            # x.x.x.x-x.x.x.x
            elsif x =~ %r{^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$}
              start_ip = IPAddr.new(Regexp.last_match(1), Socket::AF_INET)
              end_ip   = IPAddr.new(Regexp.last_match(2), Socket::AF_INET)
              range = (start_ip..end_ip).map(&:to_s)
            end
          rescue => e
            # Something went horribly wrong parsing the target IP range
            raise "Error parsing target IP range: #{e}"
          end
        end
        range
      end.compact.flatten

      # TODO: refactor this. data which matches these regexs should be taken care of above
      url_list = url_list.select { |x| !(x =~ %r{^[0-9\.\-*\/]+$}) || x =~ /^[\d\.]+$/ }
      url_list += ip_range unless ip_range.empty?

      # 使url更友好，测试如果它是一个文件，如果测试不假设它是 http:// 和 https://
      url_list = url_list.flat_map do |x|
        if File.exist?(x)
          x
        else
          # 替换URL中的%insert%字符串 # use url pattern
          x = x.gsub('%insert%',opts[:url_pattern]) unless opts[:url_pattern].to_s.eql?('')
          # 添加 url前缀和url后缀 # add prefix & suffix
          x = "#{opts[:url_prefix]}#{x}#{opts[:url_suffix]}"
          # 在没有输入协议的时候 分别添加http和https头部
          x.match(%r{^[a-z]+:\/\/}) ? x : ["http://#{x}", "https://#{x}"]
        end
      end.flatten.compact

      # TODO: refactor this
      url_list = url_list.map do |x|
        if File.exist?(x)
          x
        else
          # is it a valid domain?
          begin
            domain = Addressable::URI.parse(x)
            # check validity
            raise 'Unable to parse invalid target. No hostname.' if domain.host.empty?
            # convert IDN domain
            x = domain.normalize.to_s if domain.host !~ %r{^[a-zA-Z0-9\.:\/]*$}
          rescue => e
            # if it fails it's not valid
            x = nil
            # TODO: print something more useful
            error("Unable to parse invalid target #{x}: #{e}")
          end
          x
        end
      end

      # compact removes nils
      url_list = url_list.flatten.compact #.uniq
      if $ADD_PATH 
          #在此对所有目标插入常用路径
          url_list.uniq.dup.each do  |item|  
              $ADD_PATHS.uniq.each do  |path|  
                  base_uri = URI.join(item, path).to_s #URI.join是动态添加,当suffix是/开头时从域名添加，否则从最后一层目录添加
                  #puts base_uri
                  url_list << base_uri if (not url_list.include?(base_uri))
                end
            end
      end
      # compact removes nils
      url_list = url_list.flatten.compact.uniq  #.sort #数组.uniq.flatten.compact会影响顺序
    end
  end
end
