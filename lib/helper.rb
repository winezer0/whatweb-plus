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

#
# Helper methods for output and conversion
#
module Helper

  # converts Hash, Array, or String to UTF-8
  def self.utf8_elements!(obj)
    if obj.class == Hash
      obj.each_value do |x|
        utf8_elements!(x)
      end
    elsif obj.class == Array
      obj.each do |x|
        utf8_elements!(x)
      end
    elsif obj.class == String
      convert_to_utf8(obj)
    end
  end

  # converts a string to UTF-8
  def self.convert_to_utf8(str)
    begin
      if (str.frozen?)
        str.dup.force_encoding("UTF-8").scrub
      else
        str.force_encoding("UTF-8").scrub
      end
    rescue => e
      raise "Can't convert to UTF-8 #{e}"
    end
  end

  #
  # Takes an integer of certainty (between 1 - 100)
  #
  # returns String a word representing the certainty
  #
  def self.certainty_to_words(certainty)
    case certainty
    when 0..49
      'maybe'
    when 50..99
      'probably'
    when 100
      'certain'
    end
  end

  #
  # Word wraps a string. Used by plugin_info and OutputVerbose.
  #
  # returns Array an array of lines.
  #
  def self.word_wrap(str, width = 10)
    ret = []
    line = ''

    str.to_s.split.each do |word|
      if line.size + word.size + 1 <= width
        line += "#{word} "
        next
      end

      ret << line

      if word.size <= width
        line = "#{word} "
        next
      end

      line = ''
      w = word.clone

      while w.size > width
        ret << w[0..(width - 1)]
        w = w[width.to_i..-1]
      end

      ret << w unless w.empty?
    end

    ret << line unless line.empty?
    ret
  end

################
  def self.reencode(body, content_type=nil)
    if body.encoding == Encoding::ASCII_8BIT
      encoding = nil
  
      # look for a Byte Order Mark (BOM)
      initial_bytes = body[0..2].bytes
      if initial_bytes[0..2] == [0xEF, 0xBB, 0xBF]
        encoding = Encoding::UTF_8
      elsif initial_bytes[0..1] == [0xFE, 0xFF]
        encoding = Encoding::UTF_16BE
      elsif initial_bytes[0..1] == [0xFF, 0xFE]
        encoding = Encoding::UTF_16LE
      end
  
      # look for a charset in a content-encoding header
      if content_type
        encoding ||= content_type[/charset=["']?(.*?)($|["';\s])/i, 1]
      end
  
      # look for a charset in a meta tag in the first 1024 bytes
      if not encoding
        data = body[0..1023].gsub(/<!--.*?(-->|\Z)/m, '')
        data.scan(/<meta.*?>/m).each do |meta|
          encoding ||= meta[/charset=["']?([^>]*?)($|["'\s>])/im, 1]
        end
      end
  
      # if all else fails, default to the official default encoding for HTML
      encoding ||= Encoding::ISO_8859_1
  
      # change the encoding to match the detected or inferred encoding
      body = body.dup
      begin
        body.force_encoding(encoding)
      rescue ArgumentError
        body.force_encoding(Encoding::ISO_8859_1)
      end
    end
  
    body.encode(Encoding::UTF_8)
    
    #doc = parse(reencode(response.body, response['content-type']), options)
  end
################

end
