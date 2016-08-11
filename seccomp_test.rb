require 'seccomp'

puts "A"
gets
puts "B"

filter=Seccomp.new
filter.deny :read
filter.load
filter.release

puts "C"
gets
puts "D"
