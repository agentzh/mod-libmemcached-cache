.PHONY: all dist install clean

MOD_CACHE_SRC_DIR=../httpd-2.2.11/modules/cache
LIBMEMCACHED=/opt/libmemcached
LIBMEMCACHED_INCLUDE=$(LIBMEMCACHED)/include
LIBMEMCACHED_LIB=$(LIBMEMCACHED)/lib
APXS=/opt/apache2/bin/apxs

version=`grep 'MOD_LIBMEMCACHED_CACHE_VERSION' mod_libmemcached_cache.h | sed 's/.*"\(.*\)".*/\1/'`
dist_name=mod-libmemcached-cache-$(version)

target = mod_libmemcached_cache.la

all: $(target)

$(target): mod_libmemcached_cache.c mod_libmemcached_cache.h
	RUNPATH=$(LIBMEMCACHED_LIB) $(APXS) -L$(LIBMEMCACHED_LIB) -lmemcached -I$(MOD_CACHE_SRC_DIR) -I$(LIBMEMCACHED_INCLUDE) -c $<

install: all
	$(APXS) -a -i -n libmemcached_cache $(target)

clean:
	-rm -rf .libs dist
	-rm *.slo *.la *.lo *.o *.tar *.tar.gz

dist:
	-rm -rf dist
	-mkdir dist
	echo $(version)
	cp *.c *.h README LICENSE Makefile dist/
	tar cvf $(dist_name).tar dist/
	gzip -f --best $(dist_name).tar
	@echo $(dist_name).tar.gz generated.

