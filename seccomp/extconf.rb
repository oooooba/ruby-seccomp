require 'mkmf'
$libs=append_library($libs, "seccomp")
create_makefile('seccomp')
