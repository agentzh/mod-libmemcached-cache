LIBMEMCACHED=/opt/libmemcached
LIBMEMCACHED_INCLUDE=$(LIBMEMCACHED)/include
LIBMEMCACHED_LIB=$(LIBMEMCACHED)/lib
MOD_CACHE_SRC_DIR=../httpd-2.2.11/modules/cache

builddir     = .

top_dir      = /usr/local/apache2

top_srcdir   = ${top_dir}
top_builddir = ${top_dir}
VPATH = arch/unix/

include ${top_builddir}/build/special.mk

APXS      = apxs
APACHECTL = apachectl
EXTRA_CFLAGS = -I$(builddir) -L$(LIBMEMCACHED_LIB) -lmemcached -I$(MOD_CACHE_SRC_DIR) -I$(LIBMEMCACHED_INCLUDE)

version=`grep 'MOD_LIBMEMCACHED_CACHE_VERSION' mod_libmemcached_cache.h | sed 's/.*"\(.*\)".*/\1/'`

dist_name=mod-libmemcached-cache-$(version)

target = mod_libmemcached_cache.la

all: local-shared-build

clean: force
	-rm -rf .libs dist
	-rm *.slo *.la *.lo *.o *.tar *.tar.gz

dist: force
	-rm -rf $(dist_name)
	-mkdir $(dist_name)
	echo $(version)
	cp *.c *.h README LICENSE *.mk .deps Makefile $(dist_name)
	tar cvf $(dist_name).tar $(dist_name)
	gzip -f --best $(dist_name).tar
	@echo $(dist_name).tar.gz generated.

force:

