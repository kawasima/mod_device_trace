/* 
**  mod_device_trace.c -- Apache sample device_trace module
**  [Autogenerated via ``apxs -n device_trace -g'']
**
**  To play with this sample module first compile it into a
**  DSO file and install it into Apache's modules directory 
**  by running:
**
**    $ apxs -c -i mod_device_trace.c
**
**  Then activate it in Apache's apache2.conf file for instance
**  for the URL /private in as follows:
**
**    #   apache2.conf
**    LoadModule device_trace_module modules/mod_device_trace.so
**    <Location /private>
**    DeviceTrace On
**    </Location>
**
*/ 

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_log.h"

#include "apr_sha1.h"
#include "apr_dbd.h"
#include "mod_dbd.h"
#include "apr_strings.h"
#include "apreq2/apreq_cookie.h"
#include "apreq2/apreq_util.h"

#define MOD_PREFIX "mod_device_trace:"

typedef struct {
    int enabled;
    char *device_token_name;
    char *device_session_name;
    char *hmac_key;
    char *url_set_token;
    char *url_start_session;
    char *find_token_sql;
} device_trace_dir_conf;

module AP_MODULE_DECLARE_DATA device_trace_module;

static void *create_device_trace_dir_config(apr_pool_t *p, char *dummy) {
    device_trace_dir_conf *conf = (device_trace_dir_conf *)apr_palloc(p, sizeof(device_trace_dir_conf));
    conf->enabled = 0;
    conf->device_token_name = "device_token";
    conf->device_session_name = "device_session";
    conf->hmac_key = "kagidesu";
    conf->find_token_sql = "SELECT * FROM user_devices WHERE token = %s";
    conf->url_set_token = conf->url_start_session = NULL;
    return (void *)conf;
}

static void *merge_device_trace_dir_config(apr_pool_t *p, void *basev, void *overridesv) {
  device_trace_dir_conf *newconf = (device_trace_dir_conf *)apr_palloc(p, sizeof(device_trace_dir_conf));
  device_trace_dir_conf *base = basev;
  device_trace_dir_conf *overrides = overridesv;

  newconf->enabled = overrides->enabled;
  if (overrides->device_token_name != NULL)
    newconf->device_token_name = overrides->device_token_name;

  if (overrides->device_session_name != NULL)
    newconf->device_session_name = overrides->device_session_name;

  if (overrides->hmac_key != NULL)
    newconf->hmac_key = overrides->hmac_key;

  if (overrides->find_token_sql != NULL)
    newconf->find_token_sql = overrides->find_token_sql;

  if (overrides->url_set_token != NULL)
    newconf->url_set_token = overrides->url_set_token;

  if (overrides->url_start_session != NULL)
    newconf->url_start_session = overrides->url_start_session;

  return newconf;
}

static const char *set_enabled(cmd_parms *parms, void *dconf, int flag)
{
    device_trace_dir_conf *conf = dconf;
    conf->enabled = flag;

    return NULL;
}

static apr_table_t *get_cookie_jar(request_rec *r) {
    apr_status_t rv;
    apr_table_t *cookie_jar;
    const char *cookie_string;

    cookie_string = apr_table_get (r->headers_in, "Cookie");
    if (cookie_string == NULL)
	return NULL;

    cookie_jar = apr_table_make(r->pool, 1);
    rv = apreq_parse_cookie_header(r->pool, cookie_jar, cookie_string);
    if (rv != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, MOD_PREFIX "cookie_parse_error");
    }
    return cookie_jar;
}
static char *generate_device_session(const char *device_token, const char *key, request_rec *r) {
    unsigned char hash[APR_SHA1_DIGESTSIZE];
    unsigned char hash_b64[APR_SHA1_DIGESTSIZE * 2];
    char *expires;
    char *message;

    apr_time_t time = apr_time_sec(apr_time_now());
    expires = apr_itoa(r->pool, time + 24 * 60 * 60);

    message = apr_pstrcat(r->pool, expires, device_token, NULL);
    hmac_sha1(key, strlen(key), message, strlen(message), hash, APR_SHA1_DIGESTSIZE);
    apr_base64_encode(hash_b64, hash, APR_SHA1_DIGESTSIZE);
    
    return apr_pstrcat(r->pool, expires, "$", hash_b64, NULL);
}

static int check_device_session(const char *device_session, const char *device_token, const char *key, request_rec *r) {
    char *expires;
    char *message;
    char *session_hash_b64;
    char session_hash[APR_SHA1_DIGESTSIZE];
    unsigned char hash[APR_SHA1_DIGESTSIZE];

    char *device_session_dup = apr_pstrdup(r->pool, device_session);
    expires = apr_strtok(device_session_dup, "$", &session_hash_b64);
    
    if (expires == NULL || session_hash_b64 == NULL)
	return 0;
    
    apr_base64_decode(session_hash, session_hash_b64);
    message = apr_pstrcat(r->pool, expires, device_token, NULL);
    hmac_sha1(key, strlen(key), message, strlen(message), hash, APR_SHA1_DIGESTSIZE);

    apr_int64_t tm = apr_atoi64(expires);
    apr_time_t now = apr_time_sec(apr_time_now());

    if (strncmp(hash, (unsigned char*)session_hash, APR_SHA1_DIGESTSIZE) == 0 && now < tm) {
	return 1;
    } else {
	return 0;
    }
}

static int redirect_to_set_token(request_rec *r, char *redirect_url) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		  MOD_PREFIX "device_token is not found");
    if (redirect_url == NULL) {
	return HTTP_FORBIDDEN;
    } else {
	apr_table_set(r->headers_out, "Location", redirect_url);
	return HTTP_MOVED_TEMPORARILY;
    }
}
static int check_device_token(request_rec *r)
{
    apr_status_t rv;
    apr_dbd_results_t *rs = NULL;
    apr_dbd_row_t *row = NULL;
    apr_dbd_prepared_t *stmt = NULL;
    apr_table_t *cookie_jar = NULL;
    const char *device_token = NULL;
    char *device_session = NULL;

    device_trace_dir_conf *conf = ap_get_module_config(r->per_dir_config,
							 &device_trace_module);
    if (!conf->enabled)
	return DECLINED;
    
    cookie_jar = get_cookie_jar(r);
    if (cookie_jar != NULL)
	device_token = apr_table_get(cookie_jar, conf->device_token_name);

    if (device_token == NULL) {
	return redirect_to_set_token(r, conf->url_set_token);
    }

    if (cookie_jar != NULL) 
	device_session = (char*)apr_table_get(cookie_jar, conf->device_session_name);

    if (device_session != NULL) {
	apreq_unescape(device_session);
	if (check_device_session(device_session, device_token, conf->hmac_key, r))
	    return OK;
    }

    ap_dbd_t *dbd = ap_dbd_acquire(r);
    if (dbd == NULL) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      MOD_PREFIX "failure ap_db_acquire");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (apr_dbd_prepare(dbd->driver, r->pool, dbd->handle, conf->find_token_sql, NULL, &stmt) != APR_SUCCESS) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      MOD_PREFIX "failure apr_dbd_prepare");
	return HTTP_INTERNAL_SERVER_ERROR;
    }

    const char *params[1];
    params[0] = device_token;
    if (apr_dbd_pselect(dbd->driver, r->pool, dbd->handle, &rs, stmt, 0, 0, params) != APR_SUCCESS) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		      MOD_PREFIX "failure apr_dbd_pselect");
	return HTTP_INTERNAL_SERVER_ERROR;
    }
    rv = apr_dbd_get_row(dbd->driver, r->pool, rs, &row, -1);

    if (rv == 0) {
	if (conf->url_start_session == NULL) { 
	    device_session = generate_device_session(device_token, conf->hmac_key, r);
	    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			  MOD_PREFIX "device_session=%s", device_session);
	    apreq_cookie_t *device_session_cookie
		= apreq_cookie_make(r->pool,
				    conf->device_session_name, strlen(conf->device_session_name),
				    device_session, strlen(device_session));
	    apr_table_addn(r->err_headers_out, "Set-Cookie", apreq_cookie_as_string(device_session_cookie, r->pool));
	} else {
            apr_uri_t url;
            char *back_url = NULL;
            if (apr_uri_parse(r->pool, conf->url_start_session, &url) != APR_SUCCESS) {
	        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
	    		      MOD_PREFIX "Can't parse DeviceTokenUrlStartSession");
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            back_url = apreq_escape(r->pool, r->uri, strlen(r->uri));
            url.query = apr_pstrcat(r->pool,(url.query == NULL)?"" : url.query, "&back_url=", back_url, NULL);
	    apr_table_set(r->headers_out, "Location", apr_uri_unparse(r->pool, &url, 0));
	    return HTTP_MOVED_TEMPORARILY;
	}
    } else {
	return redirect_to_set_token(r, conf->url_set_token);
    }
    return OK;
}

static const command_rec device_trace_cmds[] = {
    AP_INIT_FLAG("DeviceTrace", set_enabled, NULL, RSRC_CONF|ACCESS_CONF,
		 "DeviceTrace Engine"),
    AP_INIT_TAKE1("DeviceTraceTokenName", ap_set_string_slot, (void *)APR_OFFSETOF(device_trace_dir_conf, device_token_name),
		  RSRC_CONF|ACCESS_CONF, "cookie name of device_token"),
    AP_INIT_TAKE1("DeviceTraceSessionName", ap_set_string_slot, (void *)APR_OFFSETOF(device_trace_dir_conf, device_session_name),
		  RSRC_CONF|ACCESS_CONF, "cookie name of device_session"),
    AP_INIT_TAKE1("DeviceTraceSecretKey", ap_set_string_slot, (void *)APR_OFFSETOF(device_trace_dir_conf, hmac_key),
		  RSRC_CONF|ACCESS_CONF, "A secret key for HMAC-SHA1"),
    AP_INIT_TAKE1("DeviceTraceSetTokenUrl", ap_set_string_slot, (void *)APR_OFFSETOF(device_trace_dir_conf, url_set_token),
		  RSRC_CONF|ACCESS_CONF, "A url"),
    AP_INIT_TAKE1("DeviceTraceStartSessionUrl", ap_set_string_slot, (void *)APR_OFFSETOF(device_trace_dir_conf, url_start_session),
		  RSRC_CONF|ACCESS_CONF, "A url"),
    AP_INIT_TAKE1("DeviceTraceFindTokenSql", ap_set_string_slot, (void *)APR_OFFSETOF(device_trace_dir_conf, find_token_sql),
		  RSRC_CONF|ACCESS_CONF, "A url"),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_access_checker(check_device_token, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA device_trace_module = {
    STANDARD20_MODULE_STUFF, 
    create_device_trace_dir_config, /* create per-dir    config structures */
    merge_device_trace_dir_config,  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    device_trace_cmds,   /* table of config file commands       */
    register_hooks  /* register hooks                      */
};

