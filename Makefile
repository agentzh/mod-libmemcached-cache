MOD_CACHE_SRC_DIR=../httpd-2.2.11/modules/cache
LIBMEMCACHED_INCLUDE=/opt/libmemcached/include
LIBMEMCACHED_LIB=/opt/libmemcached/lib
APXS=/opt/apache2/bin/apxs

target = mod_libmemcached_cache.la

all: $(target)

$(target): mod_libmemcached_cache.c mod_libmemcached_cache.h
	RUNPATH=$(LIBMEMCACHED_LIB) $(APXS) -L$(LIBMEMCACHED_LIB) -lmemcached -I$(MOD_CACHE_SRC_DIR) -I$(LIBMEMCACHED_INCLUDE) -c $<

install: all
	$(APXS) -a -i -n libmemcached_cache $(target)

