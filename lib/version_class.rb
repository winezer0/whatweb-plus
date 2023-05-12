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

class Version
  def initialize(name_product = nil, versions = nil, url = nil)
    raise 'You must specify the name of the product' if name_product.nil?
    raise 'You must specify the available versions of the product' if versions.nil?
    raise 'You must specify the available url of the website' if url.nil?

    @name = name_product
    @versions = versions
    @files = Hash['filenames' => [], 'files' => [], 'md5' => []]
    @url = url
    @got_best_versions = false
    @best_versions = []

    versions.each do |version|
      version[1].each do |file|
        next if @files['filenames'].include? file[0]
        @files['filenames'].push(file[0])
        @files['files'].push(URI.join(@url.to_s, file[0]).to_s)
        _status, url, _ip, body, _headers = open_target(@files['files'].last)
        @files['md5'].push(Digest::MD5.hexdigest(body))
      end
    end
  end

  def best_matches
    return @best_versions if @got_best_versions == true

    @versions.each do |version|
      count = 0
      version[1].each do |file|
        i = @files['filenames'].index(file[0])
        count += 1 if @files['md5'][i] == file[1]
      end
      while !@best_versions.empty? && @best_versions[0][1] < count
        @best_versions.delete_at(0)
      end
      if count > 0 && (@best_versions.empty? || @best_versions[0][1] == count) && \
         !@best_versions.include?([version[0], count])
        @best_versions.insert(0, [version[0], count])
      end
    end

    @got_best_versions = true
    @best_versions.flatten!

    @best_versions.each_index { |i| @best_versions.delete_at(i + 1) }.sort!

    @best_versions
  end

  def matches_format
    best_matches if @got_best_versions == false
    @best_versions
  end
end
