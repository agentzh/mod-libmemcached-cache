#include "apr_strings.h"
#include "util_filter.h"
#include "util_script.h"
#include "ap_config.h"
#include "ap_mpm.h"
#include "mod_libmemcached_cache.h"

enum {
    DEFAULT_MIN_CACHE_OBJECT_SIZE = 1,
    DEFAULT_MAX_CACHE_OBJECT_SIZE = 1024 * 1024,
    DEFAULT_MAX_STREAMING_BUFFER_SIZE = 1024 * 1024
};

module AP_MODULE_DECLARE_DATA libmemcached_cache_module;

/* Forward declarations */

static char* serialize_table(apr_pool_t *p, apr_table_t *table);
static char* read_table(request_rec *r, char *buf, apr_size_t buf_size, apr_table_t *table);

static int open_entity(cache_handle_t *h, request_rec *r, const char *key);
static apr_status_t recall_headers(cache_handle_t *h, request_rec *r);
static apr_status_t recall_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb);

static apr_status_t create_entity(cache_handle_t *h, request_rec *r, const char *key, apr_off_t len);
static apr_status_t store_headers(cache_handle_t *h, request_rec *r, cache_info *info);
static apr_status_t store_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *bb);

static int remove_entity(cache_handle_t *h);
static int remove_url(cache_handle_t *h, apr_pool_t *p);

/* global cache conf object */
static libmem_cache_conf_t *sconf;

/* implementations of the static functions */

static apr_status_t store_pair(request_rec *r, char *key, char *value, size_t value_len, cache_info* info) {
    memcached_return rc;
    time_t expire = info->expire / MSEC_ONE_SEC;

    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }

    rc = memcached_set(sconf->memc, key, strlen(key), value, value_len,
            expire, (uint32_t)0);

    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }

    if (rc != MEMCACHED_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "Failed to set the key %s to the memcached servers: %s",
                key, memcached_strerror(sconf->memc, rc));
        return APR_EGENERAL;
    }
    return APR_SUCCESS;
}

static char* serialize_table(apr_pool_t *p, apr_table_t *table) {
    struct iovec *iov;
    int nvec, nelts;
    int i, k;
    const apr_table_entry_t *elts;

    elts = (const apr_table_entry_t *)apr_table_elts(table)->elts;
    nelts = apr_table_elts(table)->nelts;
    nvec = nelts * 4 + 1;
    iov = apr_palloc(p, sizeof(struct iovec) * nvec);
    for (i = 0, k = 0; i < nelts; i++) {
        if (elts[i].key != NULL) {
            iov[k].iov_base = elts[i].key;
            iov[k].iov_len = strlen(elts[i].key);
            k++;
            iov[k].iov_base = ": ";
            iov[k].iov_len = sizeof(": ") - 1;
            k++;
            iov[k].iov_base = elts[i].val;
            iov[k].iov_len = strlen(elts[i].val);
            k++;
            iov[k].iov_base = "\n";
            iov[k].iov_len = 1;
            k++;
        }
    }
    iov[k].iov_base = "\n";
    iov[k].iov_len = 1;
    k++;
    return apr_pstrcatv(p, iov, k, NULL);
}

static char* read_table(request_rec *r, char *buf, apr_size_t buf_size, apr_table_t *table) {
    char *l, *w, *eol;
    for (w = buf; *w != '\0'; w = eol + 1) {
        if ((eol = strchr(w, '\n')) != NULL) {
            *eol = '\0';
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
              "libmemcached_cache: Bad header from the cache: missing terminal newline: %s", w);
            return NULL;
        }
        if (*w == '\0') { /* found the terminal CRLF where w == eol */
            return eol + 1;
        }

        if (!(l = strchr(w, ':'))) {
            /* ignore loudly */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
              "libmemcached_cache: Ignored bad header from the cache: %s", w);
        } else {
            *l++ = '\0';
            while (*l && apr_isspace(*l)) {
                ++l;
            }
            apr_table_add(table, w, l);
        }
    }
    return w;
}

static apr_status_t free_pointer (void* p) {
    free(p);
    return APR_SUCCESS;
}

static char* parse_cache_info(request_rec *r, char *buf, cache_info* info) {
    char *l, *w, *eol;
    for (w = buf; *w != '\0'; w = eol + 1) {
        if ((eol = strchr(w, '\n')) != NULL) {
            *eol = '\0';
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
              "libmemcached_cache: Bad cache info line from the cache: missing terminal newline: %s", w);
            return NULL;
        }
        if (*w == '\0') { /* found the terminal CRLF where w == eol */
            return eol + 1;
        }

        if (!(l = strchr(w, ':'))) {
            /* ignore loudly */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
              "libmemcached_cache: Ignored bad header from the cache: %s", w);
        } else {
            *l++ = '\0';
            while (*l && apr_isspace(*l)) {
                ++l;
            }
            if (strcmp(w, "status") == 0) {
                info->status = atoi(l);
            } else if (strcmp(w, "date") == 0) {
                info->date = apr_atoi64(l);
            } else if (strcmp(w, "expire") == 0) {
                info->expire = apr_atoi64(l);
            } else if (strcmp(w, "request_time") == 0) {
                info->request_time = apr_atoi64(l);
            } else if (strcmp(w, "response_time") == 0) {
                info->response_time = apr_atoi64(l);
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                  "libmemcached_cache: Unknown cache info field: %s (Only 'status', 'date', 'expire', 'request_time', and 'response_time' are expected.)", w);
                return NULL;

            }
        }
    }
    return w;
}

static char* serialize_cache_info(apr_pool_t *p, cache_info* info) {
    return apr_pstrcat(
        p,
        apr_psprintf(p, "status: %d\n", info->status),
        apr_psprintf(p, "date: " APR_TIME_T_FMT "\n", info->date),
        apr_psprintf(p, "expire: " APR_TIME_T_FMT "\n", info->expire),
        apr_psprintf(p, "request_time: " APR_TIME_T_FMT "\n", info->request_time),
        apr_psprintf(p, "response: " APR_TIME_T_FMT "\n", info->response_time),
        NULL);
}

static int open_entity(cache_handle_t *h, request_rec *r, const char *key) {
    cache_object_t *obj;
    cache_info *info;
    libmem_cache_object_t *lobj;
    memcached_return rc;
    char *keys[2];
    size_t key_len[2];
    uint32_t flags;
    unsigned int count;
    char ret_key[MEMCACHED_MAX_KEY];
    size_t ret_key_len, ret_val_len;
    char *ret_val;

    h->cache_obj = obj = apr_pcalloc(r->pool, sizeof(*obj));
    obj->vobj = lobj = apr_pcalloc(r->pool, sizeof(*lobj));
    info = &(obj->info);
    //lobj->key = md5(key);

    keys[0] = apr_pstrcat(r->pool, key, ".header", NULL);
    key_len[0] = strlen(keys[0]);

    keys[1] = apr_pstrcat(r->pool, key, ".data", NULL);
    key_len[1] = strlen(keys[1]);

    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }

    rc = memcached_mget(sconf->memc, keys, key_len, 2);
    if (rc != MEMCACHED_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "libmemcached_cache: Failed to call memcached_mget: %s",
                memcached_strerror(sconf->memc, rc));

        if (sconf->lock) {
            apr_thread_mutex_unlock(sconf->lock);
        }

        return DECLINED;
    }

    count = 0;
    while ((ret_val = memcached_fetch(sconf->memc, ret_key, &ret_key_len,
                &ret_val_len, &flags, &rc))) {
        count++;
        apr_pool_cleanup_register(r->pool, ret_val, free_pointer, apr_pool_cleanup_null);
        ret_val[ret_val_len - 1] = '\0'; /* prevent memory overflow */
        if (ret_key_len == key_len[0]) {
            /* Found the header file */
            char *p = parse_cache_info(r, ret_val, info);
            if (p == NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "libmemcached_cache: Failed to parse the info record in the header file.");
                continue;
            }
            lobj->hdrs_str = p;
        } else if (ret_key_len == key_len[1]) {
            /* Found the data file */
            lobj->body = ret_val;
        } else {
            ret_key[ret_key_len - 1] = '\0';
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    "libmemcached_cache: Unknown key returned: %s", ret_key);
        }
    }

    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }

    if (count > 0 && count != 2) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "libmemcached_cache: Found %d components for url %s but two was expected.", count, key);
        return DECLINED;
    }

    return OK;
}

static apr_status_t recall_headers(cache_handle_t *h, request_rec *r) {
    /* apr_status_t rv; */
    cache_object_t *obj = h->cache_obj;
    libmem_cache_object_t *lobj = (libmem_cache_object_t *) obj->vobj;
    char *cur;

    if (lobj->value == NULL || lobj->value_len == 0) {
        return APR_NOTFOUND;
    }

    h->resp_hdrs = apr_table_make(r->pool, 20);
    cur = lobj->value;
    cur = read_table(r, cur, lobj->value_len, h->resp_hdrs);
    if (cur == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "libmemcached_cache: Failed to parse response headers from the cache.");
        return APR_NOTFOUND;
    }

    h->req_hdrs = apr_table_make(r->pool, 20);
    cur = read_table(r, cur, lobj->value_len - (cur - lobj->value), h->req_hdrs);
    if (cur == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "libmemcached_cache: Failed to parse request headers from the cache.");
        return APR_NOTFOUND;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
        "libmemcached_cache: Recalled headers for URL %s",
        obj->key);
    return APR_SUCCESS;
}

static apr_status_t create_entity(cache_handle_t *h, request_rec *r, const char *key, apr_off_t len) {
    cache_object_t *obj;
    libmem_cache_object_t *lobj;

    h->cache_obj = obj = apr_pcalloc(r->pool, sizeof(*obj));
    obj->vobj = lobj = apr_pcalloc(r->pool, sizeof(*lobj));
    obj->key = apr_pstrdup(r->pool, key);
    //lobj->key = md5(obj->key);

    if (len == -1) {
        len = sconf->max_streaming_buffer_size;
    }
    if (len < sconf->min_cache_object_size ||
            len > sconf->max_cache_object_size) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                "libmemcached_cache: URL %s failed the size check and will not be cached.", key);
        return DECLINED;
    }
    lobj->body_len = len + 1; /* preserve the last byte for '\0' */
    return OK;
}

static apr_status_t store_headers(cache_handle_t *h, request_rec *r, cache_info *info) {
    apr_status_t rv;
    libmem_cache_object_t *lobj = (libmem_cache_object_t *) h->cache_obj->vobj;
    char *cache_info_str = NULL, *resp_hdrs_str = NULL, *req_hdrs_str = NULL;
    char *key;

    h->cache_obj->info = *info;

    cache_info_str = serialize_cache_info(r->pool, info);


    /* we no longer store cache info in our storage */
    /*
    iov[0].iov_base = info;
    iov[0].iov_len = sizeof(cache_info);
    */

    if (r->headers_out) {
        apr_table_t *headers_out;

        headers_out = ap_cache_cacheable_hdrs_out(r->pool, r->headers_out, r->server);
        if (!apr_table_get(headers_out, "Content-Type") && r->content_type) {
            apr_table_setn(headers_out, "Content-Type",
                ap_make_content_type(r, r->content_type));
        }
        headers_out = apr_table_overlay(r->pool, headers_out, r->err_headers_out);
        resp_hdrs_str = serialize_table(r->pool, headers_out);
        if (resp_hdrs_str == NULL) {
            return APR_ENOMEM;
        }
    }

    if (r->headers_in) {
        apr_table_t *headers_in;

        headers_in = ap_cache_cacheable_hdrs_out(r->pool,
            r->headers_in, r->server);
        req_hdrs_str = serialize_table(r->pool, headers_in);
        if (req_hdrs_str == NULL) {
            return APR_ENOMEM;
        }
    }

    lobj->hdrs_str = apr_pstrcat(r->pool, cache_info_str, "\n", resp_hdrs_str, "\n", req_hdrs_str, NULL);
    key = apr_pstrcat(r->pool, lobj->key, ".header", NULL);

    rv = store_pair(r, key, lobj->hdrs_str, strlen(lobj->hdrs_str) + 1, info);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    return APR_SUCCESS;
}

static apr_status_t store_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *bb) {
    char *body;
    apr_bucket *e;
    apr_status_t rv;
    char *cur;
    cache_object_t *obj = h->cache_obj;
    libmem_cache_object_t *lobj = (libmem_cache_object_t *)obj->vobj;
    char *key;

    body = apr_palloc(r->pool, lobj->body_len);
    if (body == NULL) {
        return APR_ENOMEM;
    }
    obj->count = 0;
    cur = (char*)body + obj->count;
    for (e = APR_BRIGADE_FIRST(bb);
            e != APR_BRIGADE_SENTINEL(bb); e = APR_BUCKET_NEXT(e)) {
        const char *s;
        apr_size_t len;

        if (APR_BUCKET_IS_EOS(e)) {
            break;
        }
        rv = apr_bucket_read(e, &s, &len, APR_BLOCK_READ);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        if (len) {
            /* check for buffer overflow */
            if (obj->count + len >= lobj->body_len) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                   "libmemcached_cache: content overflew.");
                len = lobj->value_len - obj->count;
                memcpy(cur, s, len - 1);
                //cur += len - 1;
                obj->count += len - 1;
                break;
            } else {
                memcpy(cur, s, len);
                cur += len;
                obj->count += len;
            }
        }
        AP_DEBUG_ASSERT(obj->count < lobj->body_len);
    }
    if (obj->count) {
        body[obj->count] = '\0';
        if (r->connection->aborted) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                "libmemcached_cache: Discarding body of size %" APR_SIZE_T_FMT " bytes for URL %s "
                "even though connection has been aborted.",
                obj->count,
                obj->key);
            return APR_EGENERAL;
        }
        lobj->body = body;

        key = apr_pstrcat(r->pool, lobj->key, ".data", NULL);
        rv = store_pair(r, key, lobj->body, obj->count + 1, &obj->info);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                 "libmemcached_cache: Failed to store body.");
            return rv;
        }
        return APR_SUCCESS;
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "libmemcached_cache: No output seen for body.");
        return APR_EGENERAL;
    }
}

/* Configuration and start-up */
static apr_status_t cleanup_memcached(void *obj) {
    memcached_free( (memcached_st*) obj );
    return APR_SUCCESS;
}

static apr_status_t cleanup_memcached_servers(void *obj) {
    memcached_server_free( (memcached_server_st*) obj );
    return APR_SUCCESS;
}

static void* create_cache_config(apr_pool_t *p, server_rec *s) {
    sconf = apr_pcalloc(p, sizeof(libmem_cache_conf_t));
    sconf->max_cache_object_size = DEFAULT_MAX_CACHE_OBJECT_SIZE;
    sconf->min_cache_object_size = DEFAULT_MIN_CACHE_OBJECT_SIZE;
    sconf->max_streaming_buffer_size = DEFAULT_MAX_STREAMING_BUFFER_SIZE;
    return sconf;
}

static int libmem_cache_post_config(apr_pool_t *p, apr_pool_t *plog,
        apr_pool_t *ptemp, server_rec *s) {
    int threaded_mpm;
    memcached_server_st *servers;
    memcached_return rc;

    /* Sanity check the cache configuration */
    if (sconf->min_cache_object_size >= sconf->max_cache_object_size) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                "LibmemCacheMaxObjectSize must be greater than LibmemCacheMinObjectSize.");
        return DONE;
    }
    if (sconf->max_streaming_buffer_size > sconf->max_cache_object_size) {
        /* Issue a notice only if something other than the default config
         * is being used */
        if (sconf->max_streaming_buffer_size != DEFAULT_MAX_STREAMING_BUFFER_SIZE &&
            sconf->max_cache_object_size != DEFAULT_MAX_CACHE_OBJECT_SIZE) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                         "LibmemCacheMaxStreamingBuffer must be less than or equal to LibmemCacheMaxObjectSize. "
                         "Resetting LibmemCacheMaxStreamingBuffer to LibmemCacheMaxObjectSize.");
        }
        sconf->max_streaming_buffer_size = sconf->max_cache_object_size;
    }
    if (sconf->max_streaming_buffer_size < sconf->min_cache_object_size) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "LibmemCacheMaxStreamingBuffer must be greater than or equal to LibmemCacheMinObjectSize. "
                     "Resetting LibmemCacheMaxStreamingBuffer to LibmemCacheMinObjectSize.");
        sconf->max_streaming_buffer_size = sconf->min_cache_object_size;
    }
    if (sconf->memc_servers == NULL || sconf->memc_servers[0] == '\0' ) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                "LibmemCacheServers must be specified.");
        return DONE;
    }

    ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm);
    if (threaded_mpm) {
        apr_thread_mutex_create(&sconf->lock, APR_THREAD_MUTEX_DEFAULT, p);
    }

    sconf->memc = memcached_create(NULL);
    if (sconf->memc == NULL) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                "LibmemCache: Failed to create the memcached_st object.");
        return DONE;
    }
    apr_pool_cleanup_register(p, sconf->memc, cleanup_memcached, apr_pool_cleanup_null);

    servers = memcached_servers_parse(sconf->memc_servers);
    if (servers == NULL) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                "Failed to create the memcached_server_st object by parsing the server list string %s", sconf->memc_servers);
        return DONE;
    }
    apr_pool_cleanup_register(p, servers, cleanup_memcached_servers, apr_pool_cleanup_null);

    rc = memcached_server_push(sconf->memc, servers);
    if (rc != MEMCACHED_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                "Failed to push servers into the memcached_st object: %s", memcached_strerror(sconf->memc, rc));
        return DONE;
    }
    memcached_behavior_set(sconf->memc, MEMCACHED_BEHAVIOR_VERIFY_KEY, 1);

    return OK;
}

static int remove_url(cache_handle_t *h, apr_pool_t *p) {
    /* XXX: stub */
    return OK;
}

static int remove_entity(cache_handle_t *h) {
    /* XXX: stub */
    return OK;
}

static const command_rec cache_cmds[] = {
    AP_INIT_TAKE1("LibmemCacheMinObjectSize", ap_set_int_slot,
        (void*)APR_OFFSETOF(libmem_cache_conf_t, min_cache_object_size), RSRC_CONF,
        "The minimum size (in bytes) of an object to be placed in the cache."),
    AP_INIT_TAKE1("LibmemCacheMaxObjectSize", ap_set_int_slot,
        (void*)APR_OFFSETOF(libmem_cache_conf_t, max_cache_object_size), RSRC_CONF,
        "The maximum size (in bytes) of an object to be placed in the cache."),
    AP_INIT_TAKE1("LibmemCacheMaxStreamingBuffer", ap_set_int_slot,
        (void*)APR_OFFSETOF(libmem_cache_conf_t, max_streaming_buffer_size), RSRC_CONF,
        "The maximum buffer size for streaming objects."),
    AP_INIT_TAKE1("LibmemCacheServers", ap_set_string_slot,
        (void*)APR_OFFSETOF(libmem_cache_conf_t, memc_servers), RSRC_CONF,
        "The memcached server list for the underlying cache."),
    {NULL}
};

static const cache_provider cache_libmem_provider = {
    &remove_entity,
    &store_headers,
    &store_body,
    &recall_headers,
    &recall_body,
    &create_entity,
    &open_entity,
    &remove_url,
};

static void register_hooks(apr_pool_t *p) {
    ap_hook_post_config(libmem_cache_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_provider(p, CACHE_PROVIDER_GROUP, "libmemcached", "0", &cache_libmem_provider);
}

module AP_MODULE_DECLARE_DATA libmemcached_cache_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    create_cache_config,
    NULL,
    cache_cmds,
    register_hooks
};

