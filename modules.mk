#
## this is used/needed by the APACHE2 build system
#
#
#MOD_FCGID = fcgid_bridge fcgid_conf fcgid_pm_main fcgid_protocol fcgid_spawn_ctl \
	mod_fcgid fcgid_proctbl_unix fcgid_pm_unix fcgid_proc_unix fcgid_bucket fcgid_filter

mod_libmemcached_cache.la: ${MOD_LIBMEMCACHED_CACHE:=.slo}
	$(SH_LINK) -rpath '$(LIBMEMCACHED_LIB):$(libexecdir)' -module -avoid-version ${MOD_LIBMEMCACHED_CACHE:=.lo}

DISTCLEAN_TARGETS = modules.mk

shared =  mod_libmemcached_cache.la

