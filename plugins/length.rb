Plugin.define do
name "length"
authors [
"Andrew Horton",

]
version "0.1"
description "The length of the HTML body"
passive do
[{:string=>@body.size}]
end
end
