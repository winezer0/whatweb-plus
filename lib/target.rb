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

# backwards compatible convenience method for plugins to use
def open_target(url)
  newtarget = Target.new(url)
  begin
    newtarget.open
  rescue StandardError => err
    error("ERROR Opening: #{newtarget} - #{err}")
  end
  # it doesn't matter if the plugin only pulls 5 instead of 6 variables
  [newtarget.status, newtarget.uri, newtarget.ip, newtarget.body, newtarget.headers, newtarget.raw_headers]
end

def decode_html_entities(s)
  html_entities = { '&quot;' => '"', '&apos;' => "'", '&amp;' => '&', '&lt;' => '<', '&gt;' => '>' }
  s.gsub( /#{html_entities.keys.join("|")}/, html_entities)
end

### matching

# fuzzy matching ftw
def make_tag_pattern(b)
  # remove stuff between script and /script
  # don't bother with  !--, --> or noscript and /noscript
  inscript = false

  b.scan(/<([^\s>]*)/).flatten.map do |x|
    x.downcase!
    r = nil
    r = x if inscript == false
    inscript = true if x == 'script'
    (inscript = false; r = x) if x == '/script'
    r
  end.compact.join(',')
end

# some plugins want a random string in URLs
def randstr
  rand(36**8).to_s(36)
end

def match_ghdb(ghdb, body, _meta, _status, base_uri)
  # this could be made faster by creating code to eval once for each plugin

  pp 'match_ghdb', ghdb if $verbose > 2

  # take a GHDB string and turn it into code to be evaluated
  matches = [] # fill with true or false. succeeds if all true
  s = ghdb

  # does it contain intitle?
  if s =~ /intitle:/i
    # extract either the next word or the following words enclosed in "s, it can't possibly be both
    intitle = (s.scan(/intitle:"([^"]*)"/i) + s.scan(/intitle:([^"]\w+)/i)).to_s
    matches << ((body =~ /<title>[^<]*#{Regexp.escape(intitle)}[^<]*<\/title>/i).nil? ? false : true)
    # strip out the intitle: part
    s = s.gsub(/intitle:"([^"]*)"/i, '').gsub(/intitle:([^"]\w+)/i, '')
  end

  if s =~ /filetype:/i
    filetype = (s.scan(/filetype:"([^"]*)"/i) + s.scan(/filetype:([^"]\w+)/i)).to_s
    # lame method: check if the URL ends in the filetype
    unless base_uri.nil?
      unless base_uri.path.split('?')[0].nil?
        matches << ((base_uri.path.split('?')[0] =~ /#{Regexp.escape(filetype)}$/i).nil? ? false : true)
      end
    end
    s = s.gsub(/filetype:"([^"]*)"/i, '').gsub(/filetype:([^"]\w+)/i, '')
  end

  if s =~ /inurl:/i
    inurl = (s.scan(/inurl:"([^"]*)"/i) + s.scan(/inurl:([^"]\w+)/i)).flatten
    # can occur multiple times.
    inurl.each { |x| matches << ((base_uri.to_s =~ /#{Regexp.escape(x)}/i).nil? ? false : true) }
    # strip out the inurl: part
    s = s.gsub(/inurl:"([^"]*)"/i, '').gsub(/inurl:([^"]\w+)/i, '')
  end

  # split the remaining words except those enclosed in quotes, remove the quotes and sort them

  remaining_words = s.scan(/([^ "]+)|("[^"]+")/i).flatten.compact.each { |w| w.delete!('"') }.sort.uniq

  pp 'Remaining GHDB words', remaining_words if $verbose > 2

  remaining_words.each do |w|
    # does it start with a - ?
    if w[0..0] == '-'
      # reverse true/false if it begins with a -
      matches << ((body =~ /#{Regexp.escape(w[1..-1])}/i).nil? ? true : false)
    else
      w = w[1..-1] if w[0..0] == '+' # if it starts with +, ignore the 1st char
      matches << ((body =~ /#{Regexp.escape(w)}/i).nil? ? false : true)
    end
  end

  pp matches if $verbose > 2

  # if all matcbhes are true, then true
  if matches.uniq == [true]
    true
  else
    false
  end
end

#
# Target
#
class Target
  include Helper
  attr_reader :target
  attr_reader :uri, :status, :ip, :body, :raw_body, :headers, :raw_headers, :raw_response
  attr_reader :cookies
  attr_reader :md5sum
  attr_reader :mmh3sum
  attr_reader :allhashsum
  attr_reader :tag_pattern
  attr_reader :is_url, :is_file
  attr_accessor :http_options
  attr_reader :redirect_counter

  @@meta_refresh_regex = /<meta[\s]+http\-equiv[\s]*=[\s]*['"]?refresh['"]?[^>]+content[\s]*=[^>]*[0-9]+;[\s]*url=['"]?([^"'>]+)['"]?[^>]*>/i

  def pretty_print
    #	"#{target} " + [@uri,@status,@ip,@body,@headers,@raw_headers,@raw_response,@cookies,@md5sum,@mmh3sum,@allhashsum,,@tag_pattern,@is_url,@is_file].join(",")
    "URI\n#{'*' * 40}\n#{@uri}\n" \
      "status\n#{'*' * 40}\n#{@status}\n" \
      "ip\n#{'*' * 40}\n#{@ip}\n" \
      "redirects\n#{'*' * 40}\n#{@redirect_counter}\n" \
      "header\n#{'*' * 40}\n#{@headers}\n" \
      "cookies\n#{'*' * 40}\n#{@cookies}\n" \
      "raw_headers\n#{'*' * 40}\n#{@raw_headers}\n" \
      "raw_response\n#{'*' * 40}\n#{@raw_response}\n" \
      "body\n#{'*' * 40}\n#{@body}\n" \
      "raw_body\n#{'*' * 40}\n#{@raw_body}\n" \
      "md5sum\n#{'*' * 40}\n#{@md5sum}\n" \
      "mmh3sum\n#{'*' * 40}\n#{@mmh3sum}\n" \
      "allhashsum\n#{'*' * 40}\n#{@allhashsum}\n" \
      "tag_pattern\n#{'*' * 40}\n#{@tag_pattern}\n" \
      "is_url\n#{'*' * 40}\n#{@is_url}\n" \
      "is_file\n#{'*' * 40}\n#{@is_file}\n"
  end

  def to_s
    @target
  end

  def self.meta_refresh_regex
    @@meta_refresh_regex
  end

  def is_file?
    @is_file
  end

  def is_url?
    @is_url
  end

  def initialize(target = nil, redirect_counter = 0)
    @target = target
    #puts 'target',@target #editor
    @redirect_counter = redirect_counter
    @headers = {}
    @http_options = { method: 'GET' }
    #		@status=0

    @is_url = if @target =~ /^http[s]?:\/\//
                true
              else
                false
              end

    if File.exist?(@target)
      @is_file = true
      raise "Error: #{@target} is a directory" if File.directory?(@target)
      if File.readable?(@target) == false
        raise "Error: You do not have permission to view #{@target}"
      end
    else
      @is_file = false
    end

    if is_url?
      @uri = URI.parse(Addressable::URI.encode(@target))

      # is this taking control away from the user?
      # [400] http://www.alexa.com  [200] http://www.alexa.com/
      @uri.path = '/' if @uri.path.empty?
    else
      # @uri=URI.parse("file://"+@target)
      @uri = URI.parse('')
    end
  end

  def open
    if is_file?
      open_file
    else
      open_url(@http_options)
    end

    sleep $WAIT if $WAIT

    ## after open
    if @body.nil?
      # Initialize @body variable if the connection is terminated prematurely
      # This is usually caused by HTTP status codes: 101, 102, 204, 205, 305
      @body = ''
    else
      #@md5sum = Digest::MD5.hexdigest(@body)
      @tag_pattern = make_tag_pattern(@body)
      if @raw_headers
        @raw_response = @raw_headers + @body
      else
        @raw_response = @body
        @raw_headers = ''
        @cookies = []
      end
    end
  end

  def open_file
    # target is a file
    @body = File.open(@target).read

    @body = @body.encode('UTF-16', 'UTF-8', invalid: :replace, replace: '').encode('UTF-8')

    # target is a http packet file
    if @body =~ /^HTTP\/1\.\d [\d]{3} (.+)\r\n\r\n/m
      # extract http header
      @headers = {}
      pageheaders = body.to_s.split(/\r\n\r\n/).first.to_s.split(/\r\n/)
      @raw_headers = pageheaders.join("\n") + "\r\n\r\n"
      @status = pageheaders.first.scan(/^HTTP\/1\.\d ([\d]{3}) /).flatten.first.to_i
      @cookies = []
      for k in 1...pageheaders.length
        section = pageheaders[k].split(/:/).first.to_s.downcase
        if section =~ /^set-cookie$/i
          @cookies << pageheaders[k].scan(/:[\s]*(.+)$/).flatten.first
        else
          @headers[section] = pageheaders[k].scan(/:[\s]*(.+)$/).flatten.first
        end
      end
      @headers['set-cookie'] = @cookies.join("\n") unless @cookies.nil? || @cookies.empty?
      # extract html source
      if @body =~ /^HTTP\/1\.\d [\d]{3} .+?\r\n\r\n(.+)/m
        @body = @body.scan(/^HTTP\/1\.\d [\d]{3} .+?\r\n\r\n(.+)/m).flatten.first
      end
    end
  rescue StandardError => err
    raise err
  end

  def open_url(options)
    begin
      ############################################editor
      #@host = @uri.host  #edito
      @host = @uri.host+":"+ @uri.port.to_s  #editor #fix
      @refer =@uri.to_s  #editor    
      #puts @refer
      ############################################editor
      @ip = Resolv.getaddress(@uri.host) 
    rescue StandardError => err
      raise err
    end

    begin
      if $USE_PROXY == true
        http = ExtendedHTTP::Proxy($PROXY_HOST, $PROXY_PORT, $PROXY_USER, $PROXY_PASS).new(@uri.host, @uri.port)
      else
        http = ExtendedHTTP.new(@uri.host, @uri.port)
      end

      # set timeouts
      http.open_timeout = $HTTP_OPEN_TIMEOUT
      http.read_timeout = $HTTP_READ_TIMEOUT

      # if it's https://
      # i wont worry about certificates, verfication, etc
      if @uri.class == URI::HTTPS
        http.use_ssl = true
        OpenSSL::SSL::SSLContext::DEFAULT_PARAMS[:ciphers] = 'TLSv1:TLSv1.1:TLSv1.2:SSLv3:SSLv2'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      end

      getthis = @uri.path + (@uri.query.nil? ? '' : '?' + @uri.query)
      req = nil
      
      
      ############################################editor
      #puts $CUSTOM_HEADERS 
      $CUSTOM_HEADERS["HOST"]  = "#@host"   
      $CUSTOM_HEADERS["Refer"] = "#@refer"  
      
      @user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36 Edg/89.0.774.48"  #editor
      @accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
      @accept_encodind = "gzip, deflate"
      @accept_language = "zh-CN,zh;q=0.9"
      
      if $CUSTOM_HEADERS["User-Agent"].downcase.include?"whatweb" then $CUSTOM_HEADERS["User-Agent"] = @user_agent end;
      if $CUSTOM_HEADERS.has_key?("Accept") == false then $CUSTOM_HEADERS["Accept"] = @accept end;
      if $CUSTOM_HEADERS.has_key?("Accept-Encoding") == false then $CUSTOM_HEADERS["Accept-Encoding"] = @accept_encoding end;
      if $CUSTOM_HEADERS.has_key?("Accept-Language") == false then $CUSTOM_HEADERS["Accept-Language"] = @accept_language end;

      #puts $CUSTOM_HEADERS 
      ############################################editor
      if options[:method] == 'GET'
        req = ExtendedHTTP::Get.new(getthis, $CUSTOM_HEADERS)
      end
      if options[:method] == 'HEAD'
        req = ExtendedHTTP::Head.new(getthis, $CUSTOM_HEADERS)
      end
      if options[:method] == 'POST'
        req = ExtendedHTTP::Post.new(getthis, $CUSTOM_HEADERS)
        req.set_form_data(options[:data])
      end

      req.basic_auth $BASIC_AUTH_USER, $BASIC_AUTH_PASS if $BASIC_AUTH_USER

      res = http.request(req)
      @raw_headers = http.raw.join("\n")
      @headers = {}

      if res.body .nil? == false then @raw_body=res.body else @raw_body="" end;  #增加@raw_body
      @md5sum = Digest::MD5.hexdigest(@raw_body).to_s   #修复md5 hash
      @string =  Base64.strict_encode64(@raw_body).scan(/.{1,76}/).join("\n") + "\n"  #"116323821" 
      @mmh3sum = Mmh3.hash32(@string).to_s #增加mmh3 hash
      @allhashsum = "mmh3:"+mmh3sum+'-'+"md5:"+md5sum #增加所有hash和并的字符串,用于解决icon请求过多的问题
       @raw_body = Helper::reencode(@raw_body, res['content-type']).to_s  #提取 Nokogiri 模块的reencode函数用来解码,成功修复title提取时的乱码问题,
        
      @body = res.body 
      @body = Helper::convert_to_utf8(@body)  
      
      @raw_headers = Helper::convert_to_utf8(@raw_headers)

      res.each_header do |x, y| 
        newx, newy = x.dup, y.dup
        @headers[ Helper::convert_to_utf8(newx) ] = Helper::convert_to_utf8(newy)
      end

      @headers['set-cookie'] = res.get_fields('set-cookie').join("\n") unless @headers['set-cookie'].nil?
      # update cookies
      if $UPDATE_COOKIES and not @headers['set-cookie'].nil?
        res.get_fields('set-cookie').each do |raw_cookie|
          cookie = raw_cookie.split(';')[0]
          cookie_name = cookie.split('=')[0]
          cookie_pattern = Regexp.new('%s=.*?(?=$|;)' % cookie_name)
          if not $CUSTOM_HEADERS.has_key?('Cookie')
            $CUSTOM_HEADERS['Cookie'] = cookie
          elsif $CUSTOM_HEADERS['Cookie'].match(cookie_pattern)
            $CUSTOM_HEADERS['Cookie'].sub!(cookie_pattern, cookie)
          else
            $CUSTOM_HEADERS['Cookie'] += '; %s' % cookie
          end
        end
      end

      @status = res.code.to_i
      puts @uri.to_s + " [#{status}]" if $verbose > 1

    rescue StandardError => err
      raise err

    end
  end



  def get_redirection_target
    newtarget_m, newtarget_h, newtarget = nil
    begin
        #新增异常处理
            if @@meta_refresh_regex =~ @body
              metarefresh = @body.scan(@@meta_refresh_regex).flatten.first
              metarefresh = decode_html_entities(metarefresh).strip
              newtarget_m = URI.join(@target, metarefresh).to_s # this works for relative and absolute
            end

            # HTTP 3XX redirect
            if (300..399) === @status && @headers && @headers['location']
              location = @headers['location']
              begin
                newtarget_h = URI.join(@target, location).to_s
              rescue StandardError => err
                # the combinaton of the current target and the new location must be invalid 
                error("Error: Invalid redirection from #{@target} to #{location}. #{err}")
                return nil
              end
            end
            # if both meta refresh location and HTTP location are set, then the HTTP location overrides
            if newtarget_m || newtarget_h
              case $FOLLOW_REDIRECT
              when 'never'
                # no_redirects = true # this never gets back to main loop but no prob
              when 'http-only'
                newtarget = newtarget_h
              when 'meta-only'
                newtarget = newtarget_m
              when 'same-site'
                newtarget = (newtarget_h || newtarget_m) if URI.parse((newtarget_h || newtarget_m)).host == @uri.host # defaults to _h if both are present
              when 'always'
                newtarget = (newtarget_h || newtarget_m)
              else
                error('Error: Invalid REDIRECT mode')
              end
            end
      rescue Exception  => err
            # the combinaton of the current target and the new location must be invalid 
            error(err.to_s)
      end
      newtarget = nil if newtarget == @uri.to_s # circular redirection not allowed
      return newtarget
  end
end
