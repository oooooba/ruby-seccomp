# Ruby-Seccomp

Ubuntu 18.04

## Prerequisites

To install all of the dependencies on Ubuntu 18.04:
```
sudo apt install libseccomp-dev
```

## Install
To create the Makefile, run the `extconf.rb` inside `seccomp`

```
cd seccomp/
ruby extconf.rb
```

Now install ruby-seccomp using the Makefile

```
make
make install
```
