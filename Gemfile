##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# https://www.morningstarsecurity.com/research/whatweb
##  gem bundler==2.2.18
source 'http://mirrors.aliyun.com/rubygems/'

# IP Address Ranges
gem 'ipaddr','1.2.2'
gem 'mmh3','1.1.0'

# IDN Domains
gem 'addressable', '2.7.0'

# JSON logging
gem 'json','2.3.1'

# MongoDB logging - optional
group :mongo do
  #gem 'mongo'
  #gem 'rchardet'
end

# Character set detection - optional
group :rchardet do
  #gem 'rchardet'
end

# Development dependencies required for tests
group :test do
  # gem 'rake'
  # gem 'minitest'
  # gem 'rubocop'
  # gem 'rdoc','6.2.1'
  # gem 'bundler-audit'
  # gem 'simplecov', require: false
end

# Needed for debugging WhatWeb
group :development do
  gem 'pry','0.13.1', :require => false
  gem 'rb-readline','0.5.5', :require => false # needed by pry on some systems
end
