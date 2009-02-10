MOD_CACHE_SRC_DIR=../httpd-2.2.11/modules/cache
LIBMEMCACHED=/opt/libmemcached
LIBMEMCACHED_INCLUDE=$(LIBMEMCACHED)/include
LIBMEMCACHED_LIB=$(LIBMEMCACHED)/lib
APXS=/opt/apache2/bin/apxs

target = mod_libmemcached_cache.la

all: $(target)

$(target): mod_libmemcached_cache.c mod_libmemcached_cache.h
	RUNPATH=$(LIBMEMCACHED_LIB) $(APXS) -L$(LIBMEMCACHED_LIB) -lmemcached -I$(MOD_CACHE_SRC_DIR) -I$(LIBMEMCACHED_INCLUDE) -c $<

install: all
	$(APXS) -a -i -n libmemcached_cache $(target)

clean:
	-rm -rf .libs
	-rm *.slo *.la *.lo *.o

