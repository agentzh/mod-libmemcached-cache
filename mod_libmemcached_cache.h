/* mod_libmemcached_cache.h - header for mod_libmemcached_cache.c */
/*
 *    Copyright (C) 2009 Yahoo! China EEEE Works, Alibaba Inc.
 *
 *    This program is free software; you can redistribute it and/or modify it
 *    under the terms of the GNU General Public License as published by the
 *    Free Software Foundation; either version 2, or (at your option) any
 *    later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.  */

#ifndef MOD_LIBMEMCACHED_CACHE_H_
#define MOD_LIBMEMCACHED_CACHE_H_

#include "mod_cache.h"
#include "ap_provider.h"
#include <libmemcached/memcached.h>

#define MOD_LIBMEMCACHED_CACHE_VERSION "0.0.4"

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
    apr_size_t min_cache_object_size;
    apr_size_t max_cache_object_size;
    apr_size_t max_streaming_buffer_size;
    char* memc_servers;
} libmem_cache_conf_t;

#endif /* MOD_LIBMEMCACHED_CACHE_H_ */

