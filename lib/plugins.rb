# Copyright 2009 to 2020 Andrew Horton and Brendan Coles
#
# This file is part of WhatWeb.
#
# WhatWeb is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 2 of the License, or at your option) any later version.
#
# WhatWeb is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with WhatWeb.  If not, see <http://www.gnu.org/licenses/>.

class Plugin
  class << self
    attr_reader :registered_plugins, :attributes
    private :new
  end

  @registered_plugins = {}
  @attributes = %i(
    aggressive
    authors
    description
    dorks
    risk
    matches
    name
    passive
    version
    website
  )
  # 插件新增属性首先需要在@attributes增加变量


  @attributes.each do |symbol|
    define_method(symbol) do |*value, &block|
      name = "@#{symbol}"
      if block
        instance_variable_set(name, block)
      elsif !value.empty?
        instance_variable_set(name, *value)
      else
        instance_variable_get(name)
      end
    end
  end

  def initialize
    # 在 Ruby 中，initialize 是类中的一个构造方法，会在通过 Class.new 或 Class#new 创建对象实例时自动调用。
    @matches = []
    @dorks = []
    @passive = nil
    @aggressive = nil
    @variables = {}
    @website = nil
  end

  # 进行插件定义和注册
  def self.define(&block)
    # TODO: plugins should isolated # 插件应该被隔离
    p = new
    p.instance_eval(&block)
    # 在 Ruby 中，instance_eval(&block) 用于在特定对象的上下文中执行给定的代码块
    p.startup
    # TODO: make sure required attributes are set # TODO: 确保设置了所需的属性

    # Freeze the plugin attributes so they cannot be self-modified by a plugin # 冻结插件属性，使其不能被插件自行修改
    Plugin.attributes.each { |symbol| p.instance_variable_get("@#{symbol}").freeze }

    # Plugin.registered_plugins[p.name] = p
    # 进行插件注册前先判断插件的风险级别,仅注册符合风险级别要求的插件
    if ($RISK_EXACT && $RISK_LEVEL == (p.risk || $RISK_NONE)) ||
      (!$RISK_EXACT && $RISK_LEVEL <= (p.risk || $RISK_NONE))
      Plugin.registered_plugins[p.name] = p
    end
  end

  def self.shutdown_all
    Plugin.registered_plugins.each { |_, plugin| plugin.shutdown }
  end

  def version_detection?
    return false unless @matches
    !@matches.map { |m| m[:version] }.compact.empty?
  end

  # individual plugins can override this #单独的插件可以覆盖它
  def startup; end

  # individual plugins can override this #单独的插件可以覆盖它
  def shutdown; end

  def scan(target)
    scan_context = ScanContext.new(plugin: self, target: target, scanner: nil)
    scan_context.instance_variable_set(:@variables, @variables)
    scan_context.x
  end
end

class ScanContext
  def initialize(plugin: nil, target: nil, scanner: nil)
    @plugin = plugin
    @matches = plugin.matches
    define_singleton_method(:passive_scan, plugin.passive) if plugin.passive
    define_singleton_method(:aggressive_scan, plugin.aggressive) if plugin.aggressive
    @target = target
    @body = target.body
    @raw_body = target.raw_body #editor
    @headers = target.headers
    @status = target.status
    @base_uri = target.uri
    @md5sum = target.md5sum
    @mmh3sum = target.mmh3sum
    @allhashsum = target.allhashsum
    @tagpattern = target.tag_pattern
    @ip = target.ip
    @raw_response = target.raw_response
    @raw_headers = target.raw_headers
    @scanner = scanner
  end

  def make_matches(target, match)
    r = []

    # search location ##默认搜索位置
    search_context = target.body # by default
    if match[:search]
      case match[:search]
      when 'all'
        search_context = target.raw_response
      when 'uri.path'  # 合并whatweb新增位置
        search_context = target.uri.path
      when 'uri.query'   # 合并whatweb新增位置
        search_context = target.uri.query
      when 'uri.extension'   # 合并whatweb新增位置
        search_context = target.uri.path.scan(/\.(\w{3,6})$/).flatten.first
        return r if search_context.nil?
      when 'headers'
        search_context = target.raw_headers
      when /headers\[(.*)\]/
        header = Regexp.last_match(1).downcase

        if target.headers[header]
          search_context = target.headers[header]
        else
          # error "Invalid search context :search => #{match[:search]}" # 无效的搜索上下文
          return r
        end
      end
    end

    if match[:ghdb]
      r << match if match_ghdb(match[:ghdb], target.body, target.headers, target.status, target.uri)
    end

    if match[:text]
      r << match if match[:regexp_compiled] =~ search_context
    end

    if match[:md5]
      r << match if target.md5sum == match[:md5]
    end

    if match[:mmh3]
      r << match if target.mmh3sum == match[:mmh3]
    end

    if match[:allhash]
      r << match if target.allhashsum.include?match[:allhash]
    end


    if match[:tagpattern]
      r << match if target.tag_pattern == match[:tagpattern]
    end

    if match[:regexp_compiled] && search_context
      [:regexp, :account, :version, :os, :module, :model, :string, :firmware, :filepath].each do |symbol|
        next unless match[symbol] && match[symbol].class == Regexp
        regexpmatch = search_context.scan(match[:regexp_compiled])
        next if regexpmatch.empty?
        m = match.dup
        m[symbol] = regexpmatch.map do |eachmatch|
          if eachmatch.is_a?(Array) && match[:offset]
            eachmatch[match[:offset]]
          elsif eachmatch.is_a?(Array)
            eachmatch.first
          elsif eachmatch.is_a?(String)
            eachmatch
          end
        end.flatten.compact.sort.uniq
        r << m
      end
    end

    # all previous matches are OR
    # these are ARE. e.g. required if present
    return r if r.empty?

    # if url and status are present, they must both match
    #如果url和状态都存在，它们必须都匹配
    # url and status cannot be alone. there must be something else that has already matched
    # Url和状态不能单独存在。 肯定还有其他匹配的东西

    # url_matched = false
    url_matched = (not $MAX_MATCH)   #关闭URL匹配需求,直接匹配所有规则,插件中的URL只用于增加目标URL
    status_matched = false

    if match[:status]
      status_matched = true if match[:status] == target.status
    end

    if match[:url]
      # url is not relative if :url starts with /       #url不是相对的，如果:url以/开头
      # url is relative if :url starts with [^/]        #url是相对的，如果url以[^/]开头
      # url query is only checked if :url has a ?       #只检查Url查询,如果 :url有一个?
      # {:url="edit?action=stop" } will only match if the end of the path and the entire query matches.  #仅当路径的末端和整个查询匹配时才匹配。
      # :url is for URIs not regexes #url用于uri而不是正则表达式

      is_relative = if match[:url] =~ /^\//
                      false
                    else
                      true
                    end

      has_query = if match[:url] =~ /\?/
                    true
                  else
                    false
                  end

      if is_relative && !has_query
        url_matched = true if target.uri.path =~ /#{match[:url]}$/
      end

      if is_relative && has_query
        if target.uri.query
          url_matched = true if "#{target.uri.path}?#{target.uri.query}" =~ /#{match[:url]}$/
        end
      end

      if !is_relative && has_query
        if target.uri.query
          url_matched = true if "#{target.uri.path}?#{target.uri.query}" == match[:url]
        end
      end

      if !is_relative && !has_query
        url_matched = true if target.uri.path == match[:url]
      end
    end

    # determine whether to return a match #确定是否返回匹配
    if match[:status] && match[:url]
      if url_matched && status_matched
        r << match
      else
        r = []
      end
    elsif match[:status] && match[:url].nil?
      if status_matched
        r << match
      else
        r = []
      end
    elsif !match[:status] && match[:url]
      if url_matched
        r << match
      else
        r = []
      end
    elsif !match[:status] && !match[:url]
      # nothing to do
    end
    r
  end

  # execute plugin
  def x
    results = []
    unless @matches.nil?
      @matches.each do |match|
        results += make_matches(@target, match)
      end
    end

    # if the plugin has a passive method, use it
    results += passive_scan if @plugin.passive

    # 全局变量内存优化
    $URLARRAY.clear if $URLARRAY.size > 9999
    $URLARRAY_PLUGINS.clear if $URLARRAY_PLUGINS.size > 9999

    # if the plugin has an aggressive method and we're in aggressive mode, use it
    # or if we're guessing all URLs
    if ($AGGRESSION == 3 && results.any?) || ($AGGRESSION == 4)
      results += aggressive_scan if @plugin.aggressive
      # if any of our matches have a url then fetch it
      # and check the matches[]
      # later we can do some caching

      # we have no caching, so we sort the URLs to fetch and only get 1 unique url per plugin. not great..
      if @matches
        urlmath = Array.new  #临时数组,杜绝同一个插件中多个相同URL的多次访问
        @matches.map { |x| x if x[:url] }.compact.sort_by { |x| x[:url] }.map do |match|
          #puts "match",match  #每个match是一条规则 #{:url=>"fjdw4ckl", XXXXXX/}
          newbase_uri = URI.join(@base_uri.to_s, match[:url]).to_s
          #puts "match",newbase_uri #新的目标地址

          if (not $URLARRAY.include?(newbase_uri))  #如果URL已经在全局URL列表就无需访问
                #$URLARRAY << newbase_uri #不能加这一句,插件目标应该影响全局目标
                #puts "newbase_uri不在全局URL列表,需要进一步判断",newbase_uri
                if (not urlmath.include?(newbase_uri) )
                    #puts "newbase_uri不在插件URL列表,可以访问",newbase_uri
                    #puts "urlmath",urlmath
                    urlmath << newbase_uri if $MAX_MATCH==true

                    #开始进行内部扫描
                    if  $MIN_URLS
                          #puts "超级匹配模式",@base_uri.to_s
                          if (not $URLARRAY_PLUGINS.include?(@base_uri.to_s) )
                             #这里的baseurl其实是判断上一级插件的url
                             #puts "基本URL没有被插件处理过"
                             $URLARRAY_PLUGINS  << newbase_uri  #把新访问的URL加入插件访问Base URL列表
                             $URLARRAY << newbase_uri
                             $TARGET_QUEUE << Target.new(newbase_uri)
                             #puts "基本URL处理过"
                           end
                     else
                        # todo: use scanner here
                        puts "plugins requests #{newbase_uri}"
                        aggressivetarget = Target.new(newbase_uri)
                        aggressivetarget.open
                        results += make_matches(aggressivetarget, match)
                     end
                end
          end
          #        if $verbose >1
          #          puts "#{@plugin_name} Aggressive: #{aggressivetarget.uri.to_s} [#{aggressivetarget.status}]"
          #        end
        end
      end
    end
    # clean up results
    unless results.empty?
      results.each do |r|
        # default certainty is 100%
        r[:certainty] = 100 if r[:certainty].nil?
      end
    end

    results
  end
end
