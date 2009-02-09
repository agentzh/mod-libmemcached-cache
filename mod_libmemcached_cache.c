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

static apr_status_t open_entity(cache_handle_t *h, request_rec *r, const char *key);
static apr_status_t recall_headers(cache_handle_t *h, request_rec *r);
static apr_status_t recall_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb);

static apr_status_t create_entity(cache_handle_t *h, request_rec *r, const char *key, apr_off_t len);
static apr_status_t store_headers(cache_handle_t *h, request_rec *r, cache_info *info);
static apr_status_t store_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *bb);

static apr_status_t remove_entity(cache_handle_t *h);

/* global cache conf object */
static libmem_cache_conf_t *sconf;

/* implementations of the static functions */
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
            iov[k].iov_base = CRLF;
            iov[k].iov_len = sizeof(CRLF) - 1;
            k++;
        }
    }
    iov[k].iov_base = CRLF;
    iov[k].iov_len = sizeof(CRLF) - 1;
    k++;
    return apr_pstrcatv(p, iov, k, NULL);
}

static char* read_table(request_rec *r, char *buf, apr_size_t buf_size, apr_table_t *table) {
    char *l, *w, *ww;
    for (w = buf; w - buf < buf_size; w = ww + 1) {
        if ((ww = strchr(w, '\n')) != NULL) {
            if (*(ww - 1) == CR) {
                *(ww - 1) = '\0';
            }
            *ww = '\0';
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
              "libmemcached_cache: Bad header from the cache: missing terminal CRLF.");
            return NULL;
        }
        if (*w == '\0') { /* found the terminal CRLF where w == ww - 1 */
            return ww + 1;
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

static apr_status_t store_headers(cache_handle_t *h, request_rec *r, cache_info *info) {
    apr_status_t rv;
    libmem_cache_object_t *lobj = (libmem_cache_object_t *) h->cache_obj->vobj;
    char *resp_hdrs_str, *req_hdrs_str;

    h->cache_obj->info = *info;

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

    lobj->hdrs_str = apr_pstrcat(r->pool, resp_hdrs_str, req_hdrs_str, NULL);
    if (lobj->body != NULL) {
        /* we should avoid copying body here */
        rv = store_pair(r, lobj->key, apr_pstrcat(r->pool, lobj->hdrs_str, lobj->body));
        if (rv != APR_SUCCESS) {
            return rv;
        }
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
            if ((obj->count + len) > lobj->body_len) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                   "libmemcached_cache: content overflew.");
                len = lobj->value_len - obj->count;
                memcpy(cur, s, len);
                cur += len;
                obj->count += len;
                break;
            } else {
                memcpy(cur, s, len);
                cur += len;
                obj->count += len;
            }
        }
        AP_DEBUG_ASSERT(obj->count <= lobj->body_len);
    }
    if (obj->count) {
        if (r->connection->aborted) {
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server,
                "libmemcached_cache: Discarding body of size %" APR_SIZE_T_FMT " bytes for URL %s "
                "even though connection has been aborted.",
                obj->count,
                obj->key);
            return APR_EGENERAL;
        }
        lobj->body = body;

        if (lobj->hdrs_str != NULL) {
            /* we should avoid copying body here */
            rv = store_pair(r, lobj->key, apr_pstrcat(r->pool, lobj->hdrs_str, lobj->body, NULL));
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                     "libmemcached_cache: Failed to store body.");
                return rv;
            }
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
    /* stub */
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

