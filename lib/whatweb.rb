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

# Debugging
# require 'profile' # debugging

# Standard Ruby
require 'getoptlong'
require 'net/http'
require 'open-uri'
require 'cgi'
require 'thread'
require 'rbconfig' # detect environment, e.g. windows or linux
require 'resolv'
require 'resolv-replace' # asynchronous DNS
require 'open-uri'
require 'digest/md5'
require 'openssl' # required for Ruby version ~> 2.4
require 'pp'
require 'mmh3' #editor favicon hash support
require 'base64'#editor favicon hash support

# WhatWeb libs
require_relative 'whatweb/version.rb'
require_relative 'whatweb/banner.rb'
require_relative 'whatweb/scan.rb'
require_relative 'whatweb/parser.rb'
require_relative 'whatweb/redirect.rb'
require_relative 'gems.rb'
require_relative 'helper.rb'
require_relative 'target.rb'
require_relative 'plugins.rb'
require_relative 'plugin_support.rb'
require_relative 'logging.rb'
require_relative 'colour.rb'
require_relative 'version_class.rb'
require_relative 'http-status.rb'
require_relative 'extend-http.rb'

# load the lib/logging/ folder
Dir["#{File.expand_path(File.dirname(__FILE__))}/logging/*.rb"].each {|file| require file }

# Output options
$WWDEBUG = false # raise exceptions in plugins, etc
$verbose = 0 # $VERBOSE is reserved in ruby
$use_colour = 'always'
$QUIET = false
$NO_ERRORS = false
$LOG_ERRORS = nil
$PLUGIN_TIMES = Hash.new(0)

# HTTP connection options
$USER_AGENT = "WhatWeb/#{WhatWeb::VERSION}"
$AGGRESSION = 1

$RISK_NONE = 1  # 无risk标记时的默认风险等级
$RISK_LEVEL = $RISK_NONE # 选择调用插件的最小风险等级
$RISK_EXACT = false # 风险等级插件精确筛选模式, true 精确匹配模式, false 范围匹配模式

$FOLLOW_REDIRECT = 'always'
$UPDATE_COOKIES = false
$USE_PROXY = false
$PROXY_HOST = nil
$PROXY_PORT = 8080
$PROXY_USER = nil
$PROXY_PASS = nil
$HTTP_OPEN_TIMEOUT = 15
$HTTP_READ_TIMEOUT = 30
$WAIT = nil
$CUSTOM_HEADERS = {}
$BASIC_AUTH_USER = nil
$BASIC_AUTH_PASS = nil

$RANDSTR = rand(36**8).to_s(36)    #统一rangstr()调用结果, 减少访问次数

$URLARRAY = Array.new              #添加数组用于判断是否存在全局的重复URL目标

$MAX_MATCH = false                 #开启最大范围匹配包括:url里的规则,对于插件里面的URL直接加到全局目标中,实现最少访问
$MIN_URLS  = false                 #通过添加临时数组实现 最小化插件内URL请求,用于判断插件内的是否存在重复URL目标

$TARGET_QUEUE = nil                 #将任务做成全局变量,实现动态添加。
$URLARRAY_PLUGINS = Array.new       #添加数组存放插件访问的全局目标,用于URL是否是来自插件的URL

$ADD_PATH =false                    #开启$ADD_PATHS支持
$ADD_PATHS =["/favicon.ico","/","/robots.txt","/license.txt","/readme.txt","/logo.gif","/index.html"]     # 添加数组存储经常访问的路径

# Ruby Version Compatability
if Gem::Version.new(RUBY_VERSION) < Gem::Version.new(2.0)
  raise('Unsupported version of Ruby. WhatWeb requires Ruby 2.0 or later.')
end

# Initialize HTTP Status class
HTTP_Status.initialize


PLUGIN_DIRS = []

# Load plugins from only one location
# Check for plugins in folders relative to the whatweb file first
# __dir__ follows symlinks
# this will work when whatweb is a symlink in /usr/bin/
$load_path_plugins = [
  Dir.pwd,      # 当前命令行环境路径
  File.dirname(File.expand_path($PROGRAM_NAME)),      # whatweb.exe 或 whatweb.rb文件路径
  File.expand_path('../', __dir__),     # 当前rb文件的相对路径的上一级
]


# 添加自定义环境变量指定的路径
if ENV['WHATWEB_ROOT']
  $load_path_plugins << ENV['WHATWEB_ROOT']
end

is_windows = (RbConfig::CONFIG['host_os'] =~ /mswin|mingw|cygwin/)
# 添加 用户目录下的whatweb文件夹
if is_windows
  if ENV['USERPROFILE']
    $load_path_plugins << File.join(ENV['USERPROFILE'], 'whatweb')   # windows下的用户目录
  end
else
  if ENV['HOME']
    $load_path_plugins << File.join(ENV['HOME'], 'whatweb')   # Linux下的用户目录
  end
  # 添加 按照自定义安装方法设置的默认路径
  $load_path_plugins << "/opt/whatweb"
  # 添加 Makefile默认安装的路径，也在Kali中使用
  $load_path_plugins << "/usr/share/whatweb"
end

# 去重和去 nil
$load_path_plugins.uniq.compact
# puts yellow("load_path_plugins: #{$load_path_plugins.inspect}")

# 将所有路径加载到 PLUGIN_DIRS 中
$load_path_plugins.each do |dir|
	["plugins", "my-plugins"].each do |subdir|
    path = File.expand_path(subdir, dir)
	  PLUGIN_DIRS << path if Dir.exist?(path)
	end
end
# puts  yellow("load_plugin_dirs: #{PLUGIN_DIRS.inspect}")
