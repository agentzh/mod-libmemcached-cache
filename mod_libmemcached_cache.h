#ifndef MOD_LIBMEMCACHED_CACHE_H_
#define MOD_LIBMEMCACHED_CACHE_H_

#include "mod_cache.h"
#include "ap_provider.h"
#include <libmemcached/memcached.h>

typedef struct libmem_cache_object {
    char* key;  /* memcached MD5 key for the canonicalized url */
    apr_size_t key_len;  /* memcached MD5 key length */
    char* value;
    apr_size_t value_len;  /* memcached value length */
    char* hdrs_str;
    char* body;
    apr_size_t body_len;
} libmem_cache_object_t;

typedef struct libmem_cache_conf {
    apr_thread_mutex_t *lock;
    memcached_st *memc;
    apr_size_t max_cache_object_size;
} libmem_cache_conf_t;

#endif /* MOD_LIBMEMCACHED_CACHE_H_ */

