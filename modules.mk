#
## this is used/needed by the APACHE2 build system
#
#
MOD_LIBMEMCACHED_CACHE = mod_libmemcached_cache

mod_libmemcached_cache.la: ${MOD_LIBMEMCACHED_CACHE:=.slo}
	$(SH_LINK) -rpath '$(LIBMEMCACHED_LIB):$(libexecdir)' -module -avoid-version ${MOD_LIBMEMCACHED_CACHE:=.lo}

DISTCLEAN_TARGETS = modules.mk

shared =  mod_libmemcached_cache.la

