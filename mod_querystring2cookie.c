/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"


#include "apreq_util.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"

#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "http_connection.h"

#include <math.h>

/* ********************************************

    Structs & Defines

   ******************************************** */

#ifdef DEBUG                    // To print diagnostics to the error log
#define _DEBUG 1                // enable through gcc -DDEBUG
#else
#define _DEBUG 0
#endif

// General note - although folding multiple cookie key/value pairs into
// a single set-cookie header is allowed through the rfc, in practice,
// chrome doesn't seem to want them, and this posts corroborates:
// http://stackoverflow.com/questions/2880047/is-it-possible-to-set-more-than-one-cookie-with-a-single-set-cookie
// http://tools.ietf.org/html/rfc2109 - section 4.2.2  Set-Cookie Syntax

// module configuration - this is basically a global struct
typedef struct {
    int enabled;            // module enabled?
    int enabled_if_dnt;     // module enabled for requests with X-DNT?
    int encode_in_key;      // encode the pairs in the key instead of the value?
    int cookie_expires;     // holds the expires value for the cookie
    int cookie_max_size;    // maximum size of all the key/value pairs
    char *cookie_domain;    // domain the cookie will be set in
    char *cookie_prefix;    // prefix all keys in the cookie with this string
    char *cookie_name;      // use this as the cookie name, unless cookie_name_from is set
    char *cookie_name_from; // use this is as the cookie name from the query string
    char *cookie_pair_delimiter;
                            // seperate key/value pairs in the cookie with this char
    char *cookie_key_value_delimiter;
                            // seperate the key and value in a cookie with this char
    apr_array_header_t *qs_ignore;
                            // query string keys that will not be set in the cookie
} settings_rec;

module AP_MODULE_DECLARE_DATA querystring2cookie_module;

// See here for the structure of request_rec:
// http://ci.apache.org/projects/httpd/trunk/doxygen/structrequest__rec.html
static int hook(request_rec *r)
{
    settings_rec *cfg = ap_get_module_config( r->per_dir_config,
                                              &querystring2cookie_module );

    /* Do not run in subrequests, don't run if not enabled */
    if( !(cfg->enabled || r->main) ) {
        return DECLINED;
    }

    /* No query string? nothing to do here */
    if( !(r->args) || strlen( r->args ) < 1 ) {
        return DECLINED;
    }

    /* skip if dnt headers are present? */
    if( !(cfg->enabled_if_dnt) && apr_table_get( r->headers_in, "DNT" ) ) {
        _DEBUG && fprintf( stderr, "DNT header sent: declined\n" );
        return DECLINED;
    }

    _DEBUG && fprintf( stderr, "Query string: '%s'\n", r->args );

    // ***********************************
    // Calculate expiry time
    // ***********************************

    // The expiry time. We can't use max-age because IE6 - IE8 do not
    // support it :(
    char *expires = "";

    if( cfg->cookie_expires > 0 ) {

        apr_time_exp_t tms;
        apr_time_exp_gmt( &tms, r->request_time
                              + apr_time_from_sec( cfg->cookie_expires ) );

        expires = apr_psprintf( r->pool,
                            "expires=%s, %.2d-%s-%.2d %.2d:%.2d:%.2d GMT",
                            apr_day_snames[tms.tm_wday],
                            tms.tm_mday,
                            apr_month_snames[tms.tm_mon],
                            tms.tm_year % 100,
                            tms.tm_hour, tms.tm_min, tms.tm_sec
                        );
    }

    // ***********************************
    // Find key/value pairs
    // ***********************************

    // keep track of how much data we've been writing - there's a limit to how
    // much a browser will store per domain (usually 4k) so we want to make sure
    // it's not getting flooded.
    int total_pair_size = 0;

    // This holds the final cookie we'll send back - make sure to initialize
    // or it can point at garbage!
    char *cookie = "";

    // string to use as the cookie name (together with the prefix) - make sure to
    // initialize or it can point at garbage!
    char *cookie_name = "";

    // Iterate over the key/value pairs
    char *last_pair;
    char *pair = apr_strtok( apr_pstrdup( r->pool, r->args ), "&", &last_pair );

    _DEBUG && fprintf( stderr, "about to parse query string for pairs\n" );

    _DEBUG && fprintf( stderr, "looking for cookie name in %s\n", cfg->cookie_name_from );

    while( pair != NULL ) {

        // length of the substr before the = sign (or index of the = sign)
        int contains_equals_at = strcspn( pair, "=" );

        // Does not contains a =, or starts with a =, meaning it's garbage
        if( !strstr(pair, "=") || contains_equals_at < 1 ) {
            _DEBUG && fprintf( stderr, "invalid pair: %s\n", pair );

            // And get the next pair -- has to be done at every break
            pair = apr_strtok( NULL, "&", &last_pair );
            continue;
        }

        _DEBUG && fprintf( stderr, "pair looks valid: %s - = sign at pos: %i\n",
                            pair, contains_equals_at );

        // So this IS a key value pair. Let's get the key and the value.
        // first, get the key - everything up to the first =
        char *key   = apr_pstrndup( r->pool, pair, contains_equals_at );

        // now get the value, everything AFTER the = sign. We do that by
        // moving the pointer past the = sign.
        char *value = apr_pstrdup( r->pool, pair );
        value += contains_equals_at + 1;

        _DEBUG && fprintf( stderr, "pair=%s, key=%s, value=%s\n", pair, key, value );

        // you want us to use a name from the query string?
        // This might be that name.
        if( cfg->cookie_name_from && !(strlen(cookie_name)) &&
            strcasecmp( key, cfg->cookie_name_from ) == 0
        ) {
            // get everything after the = sign -- that's our name.
            cookie_name = apr_pstrcat( r->pool, cfg->cookie_prefix, value, NULL );

            _DEBUG && fprintf( stderr, "using %s as the cookie name\n", cookie_name );

            // And get the next pair -- has to be done at every break
            pair = apr_strtok( NULL, "&", &last_pair );
            continue;

        // may be on the ignore list
        } else {

            // may have to continue the outer loop, use this as a marker
            int do_continue = 0;

            // you might have blacklisted this key; let's check
            // Following tutorial code here again:
            // http://dev.ariel-networks.com/apr/apr-tutorial/html/apr-tutorial-19.html
            int i;
            for( i = 0; i < cfg->qs_ignore->nelts; i++ ) {

                char *ignore = ((char **)cfg->qs_ignore->elts)[i];

                _DEBUG && fprintf( stderr, "processing ignore %s against pair %s\n",
                                        ignore, pair );

                // it's indeed on the ignore list; move on
                // do this by comparing the string length first - if the length of
                // the ignore key and the key are identical AND the first N characters
                // of the string are the same
                if( strcasecmp( key, ignore ) == 0 ) {
                    _DEBUG && fprintf( stderr, "pair %s is on the ignore list: %s\n",
                                        pair, ignore );

                    // signal to continue the outer loop; we found an ignore match
                    do_continue = 1;
                    break;
                }
            }

            // ignore match found, move on
            if( do_continue ) {
                // And get the next pair -- has to be done at every break
                pair = apr_strtok( NULL, "&", &last_pair );
                continue;
            }
        }

        // looks like a valid key=value declaration
        _DEBUG && fprintf( stderr, "valid key/value pair: %s\n", pair );

        // Now, the key may contain URL unsafe characters, which are also
        // not allowed in Cookies. See here:
        // http://tools.ietf.org/html/rfc2068, section 2.2 on 'tspecials'
        //
        // So instead, we url encode the key. The size of the key is max
        // 3 times old key size (any char gets encoded into %xx), so allow
        // for that space. See the documentation here:
        // http://httpd.apache.org/apreq/docs/libapreq2/apreq__util_8h.html#785be2ceae273b0a7b2ffda223b2ebae
        char *escaped_key   = apreq_escape( r->pool, key, strlen(key) );
        char *escaped_value = apreq_escape( r->pool, value, strlen(value) );

        _DEBUG && fprintf( stderr, "Original key: %s - Escaped key: %s\n", key, escaped_key );
        _DEBUG && fprintf( stderr, "Original value: %s - Escaped value: %s\n", value, escaped_value );

        // Now, let's do some transposing: The '=' sign needs to be replaced
        // with whatever the separator is. It can't be a '=' sign, as that's
        // illegal in cookies. The string may be larger than a single char,
        // so split the string and do the magix.

        // This makes key[delim]value - redefining pair here is safe, we're
        // just using it for printing now.
        char *key_value = apr_pstrcat( r->pool,
                                       escaped_key,
                                       cfg->cookie_key_value_delimiter,
                                       escaped_value,
                                       NULL
                                    );

        int this_pair_size = strlen( key_value );

        // Make sure the individual pair, as well as the whole thing doesn't
        // get too long

        _DEBUG && fprintf( stderr,
                "this pair size: %i, total pair size: %i, max size: %i\n",
                this_pair_size, total_pair_size, cfg->cookie_max_size  );

        if( (this_pair_size <= cfg->cookie_max_size) &&
            (total_pair_size + this_pair_size <= cfg->cookie_max_size)
        ) {

            cookie = apr_pstrcat( r->pool,
                                  cookie,       // the cookie so far
                                  // If we already have pairs in here, we need the
                                  // delimiter, otherwise we don't.
                                  (strlen(cookie) ? cfg->cookie_pair_delimiter : ""),
                                  key_value,    // the next pair.
                                  NULL
                            );

            // update the book keeping - this is the new size including delims
            total_pair_size = strlen(cookie);

            _DEBUG && fprintf( stderr, "this pair size: %i, total pair size: %i\n",
                                    this_pair_size, total_pair_size );

        } else {
            _DEBUG && fprintf( stderr,
                "Pair size too long to add: %s (this: %i total: %i max: %i)\n",
                key_value, this_pair_size, total_pair_size, cfg->cookie_max_size );
        }

        // and move the pointer
        pair = apr_strtok( NULL, "&", &last_pair );
    }

     // So you told us we should use a cookie name from the query string,
     // but we never found it in there. That's a problem.
     if( cfg->cookie_name_from && !strlen(cookie_name) ) {

         // r->err_headers_out also honors non-2xx responses and
         // internal redirects. See the patch here:
         // http://svn.apache.org/viewvc?view=revision&revision=1154620
         apr_table_addn( r->err_headers_out,
             "X-QS2Cookie",
             apr_pstrcat( r->pool,
                 "ERROR: Did not detect cookie name - missing QS argument: ",
                 cfg->cookie_name_from,
                 NULL
             )
         );

     // Let's return the output
     } else {

         // we got here without a cookie name? We can use the default.
         if( !strlen(cookie_name) ) {
             _DEBUG && fprintf( stderr, "explicitly setting cookie name to: %s\n",
                                         cfg->cookie_name );

             cookie_name = apr_pstrcat( r->pool,
                                        cfg->cookie_prefix, cfg->cookie_name,
                                        NULL );
         }

         _DEBUG && fprintf( stderr, "cookie name: %s\n", cookie_name );

        // XXX use a sprintf format for more flexibility?
        if( cfg->encode_in_key ) {
            _DEBUG && fprintf( stderr, "%s: encoding in the key\n", cookie_name );

            cookie = apr_pstrcat( r->pool,
                            // cookie data
                            cookie_name, cfg->cookie_pair_delimiter, cookie, "=",
                            // The format is different on 32 (%ld) vs 64bit (%lld), so
                            // use the constant for it instead. You can find this in apr.h
                            apr_psprintf( r->pool, "%" APR_OFF_T_FMT, apr_time_sec(apr_time_now()) ),
                            NULL
                         );
        } else {
            _DEBUG && fprintf( stderr, "%s: encoding in the value\n", cookie_name );
            cookie = apr_pstrcat( r->pool, cookie_name, "=", cookie, NULL );

        }

        // And now add the meta data to the cookie
        cookie = apr_pstrcat( r->pool, cookie, "; ",
                                "path=/; ", cfg->cookie_domain, expires,
                                NULL );

        _DEBUG && fprintf( stderr, "cookie: %s\n", cookie );

        // r->err_headers_out also honors non-2xx responses and
        // internal redirects. See the patch here:
        // http://svn.apache.org/viewvc?view=revision&revision=1154620
        apr_table_addn( r->err_headers_out, "Set-Cookie", cookie );
    }

    return OK;
}

/* ********************************************

    Default settings

   ******************************************** */

/* initialize all attributes */
static void *init_settings(apr_pool_t *p, char *d)
{
    settings_rec *cfg;

    cfg = (settings_rec *) apr_pcalloc(p, sizeof(settings_rec));
    cfg->enabled                    = 0;
    cfg->enabled_if_dnt             = 0;
    cfg->encode_in_key              = 0;
    cfg->cookie_expires             = 0; // in seconds - so a day
    cfg->cookie_max_size            = 1024;
    cfg->cookie_name                = "qs2cookie";
    cfg->cookie_name_from           = NULL;
    cfg->cookie_domain              = "";    // used in apr_pstrcat - can't be null
    cfg->cookie_prefix              = "";    // used in apr_pstrcat - can't be null
    cfg->cookie_pair_delimiter      = "^";
    cfg->cookie_key_value_delimiter = "|";
    cfg->qs_ignore                  = apr_array_make(p, 2, sizeof(const char*) );

    return cfg;
}


/* ********************************************

    Parsing configuration options

   ******************************************** */

/* Set the value of a config variabe, strings only */
static const char *set_config_value(cmd_parms *cmd, void *mconfig,
                                    const char *value)
{
    settings_rec *cfg;

    cfg = (settings_rec *) mconfig;

    char name[50];
    sprintf( name, "%s", cmd->cmd->name );

    /*
     * Apply restrictions on attributes.
     */
    if( strlen(value) == 0 ) {
        return apr_psprintf(cmd->pool, "%s not allowed to be NULL", name);
    }

    /* Domain to set the cookie in */
    if( strcasecmp(name, "QS2CookieDomain") == 0 ) {

        if( value[0] != '.' ) {
            return "QS2CookieDomain values must begin with a dot";
        }

        if( ap_strchr_c( &value[1], '.' ) == NULL ) {
            return "QS2CookieDomain values must contain at least one embedded dot";
        }

        // immediately format it for the cookie value, as that's the only
        // place we'll be using it.
        cfg->cookie_domain =
            apr_pstrcat( cmd->pool, "domain=", value, "; ", NULL );

    /* Prefix for all keys set in the cookie */
    } else if( strcasecmp(name, "QS2CookiePrefix") == 0 ) {
        cfg->cookie_prefix     = apr_pstrdup(cmd->pool, value);

    /* Use this query string argument for the cookie name */
    } else if( strcasecmp(name, "QS2CookieName") == 0 ) {
        cfg->cookie_name       = apr_pstrdup(cmd->pool, value);

    /* Use this query string argument for the cookie name */
    } else if( strcasecmp(name, "QS2CookieNameFrom") == 0 ) {
        cfg->cookie_name_from  = apr_pstrdup(cmd->pool, value);

    /* Use this delimiter for pairs of key/values */
    } else if( strcasecmp(name, "QS2CookiePairDelimiter") == 0 ) {

        if( strcspn( value, "=" ) == 0 ) {
            return apr_psprintf(cmd->pool,
                "Variable %s may not be '=' -- illegal in cookie values", name);
        }

        cfg->cookie_pair_delimiter  = apr_pstrdup(cmd->pool, value);

    /* Use this delimiter between a key and a value */
    } else if( strcasecmp(name, "QS2CookieKeyValueDelimiter") == 0 ) {

        if( strcspn( value, "=" ) == 0 ) {
            return apr_psprintf(cmd->pool,
                "Variable %s may not be '=' -- illegal in cookie values", name);
        }

        cfg->cookie_key_value_delimiter  = apr_pstrdup(cmd->pool, value);

    /* Maximum size of all the key/value pairs */
    } else if( strcasecmp(name, "QS2CookieMaxSize") == 0 ) {

        // this has to be a number
        if( apr_isdigit(*value) && apr_isdigit(value[strlen(value) - 1]) ) {
            cfg->cookie_max_size   = atol(apr_pstrdup(cmd->pool, value));
        } else {
            return apr_psprintf(cmd->pool,
                "Variable %s must be a number, not %s", name, value);
        }

    /* Expiry time, in seconds after the request */
    } else if( strcasecmp(name, "QS2CookieExpires") == 0 ) {

        // this has to be a number
        if( apr_isdigit(*value) && apr_isdigit(value[strlen(value) - 1]) ) {
            cfg->cookie_expires = atol(apr_pstrdup(cmd->pool, value));
        } else {
            return apr_psprintf(cmd->pool,
                "Variable %s must be a number, not %s", name, value);
        }

    /* all the keys that will not be put into the cookie */
    } else if( strcasecmp(name, "QS2CookieIgnore") == 0 ) {

        // following tutorial here:
        // http://dev.ariel-networks.com/apr/apr-tutorial/html/apr-tutorial-19.html
        const char *str                                = apr_pstrdup(cmd->pool, value);
        *(const char**)apr_array_push(cfg->qs_ignore) = str;

        _DEBUG && fprintf( stderr, "qs ignore = %s\n", str );

        char *ary = apr_array_pstrcat( cmd->pool, cfg->qs_ignore, '-' );
        _DEBUG && fprintf( stderr, "qs ignore as str = %s\n", ary );

    } else {
        return apr_psprintf(cmd->pool, "No such variable %s", name);
    }

    return NULL;
}

/* Set the value of a config variabe, ints/booleans only */
static const char *set_config_enable(cmd_parms *cmd, void *mconfig,
                                    int value)
{
    settings_rec *cfg;

    cfg = (settings_rec *) mconfig;

    char name[50];
    sprintf( name, "%s", cmd->cmd->name );

    if( strcasecmp(name, "QS2Cookie") == 0 ) {
        cfg->enabled           = value;

    } else if( strcasecmp(name, "QS2CookieEnableIfDNT") == 0 ) {
        cfg->enabled_if_dnt    = value;

    } else if( strcasecmp(name, "QS2CookieEncodeInKey") == 0 ) {
        cfg->encode_in_key     = value;

    } else {
        return apr_psprintf(cmd->pool, "No such variable %s", name);
    }

    return NULL;
}

/* ********************************************

    Configuration options

   ******************************************** */

static const command_rec commands[] = {
    AP_INIT_FLAG( "QS2Cookie",              set_config_enable,  NULL, OR_FILEINFO,
                  "whether or not to enable querystring to cookie module"),
    AP_INIT_FLAG( "QS2CookieEnableIfDNT",   set_config_enable,  NULL, OR_FILEINFO,
                  "whether or not to enable cookies if 'X-DNT' header is present"),
    AP_INIT_FLAG( "QS2CookieEncodeInKey",   set_config_enable,  NULL, OR_FILEINFO,
                  "rather than encoding the pairs in the value, encode them in the key"),
    AP_INIT_TAKE1("QS2CookieExpires",       set_config_value,   NULL, OR_FILEINFO,
                  "expiry time for the cookie, in seconds after the request is served"),
    AP_INIT_TAKE1("QS2CookieDomain",        set_config_value,   NULL, OR_FILEINFO,
                  "domain to which this cookie applies"),
    AP_INIT_TAKE1("QS2CookieMaxSize",       set_config_value,   NULL, OR_FILEINFO,
                  "maximum size to allow for all the key/value pairs in this request"),
    AP_INIT_TAKE1("QS2CookiePrefix",        set_config_value,   NULL, OR_FILEINFO,
                  "prefix all cookie keys with this string"),
    AP_INIT_TAKE1("QS2CookieName",          set_config_value,   NULL, OR_FILEINFO,
                  "this will be the cookie name, unless QS2CookieNameFrom is set"),
    AP_INIT_TAKE1("QS2CookieNameFrom",      set_config_value,   NULL, OR_FILEINFO,
                  "the cookie name will come from this query paramater"),
    AP_INIT_TAKE1("QS2CookiePairDelimiter", set_config_value,   NULL, OR_FILEINFO,
                  "pairs of key/values will be delimited by this character"),
    AP_INIT_TAKE1("QS2CookieKeyValueDelimiter",
                                            set_config_value,   NULL, OR_FILEINFO,
                  "key and value will be delimited by this character"),
    AP_INIT_ITERATE( "QS2CookieIgnore",     set_config_value,   NULL, OR_FILEINFO,
                  "list of query string keys that will not be set in the cookie" ),
    {NULL}
};

/* ********************************************

    Register module to Apache

   ******************************************** */

static void register_hooks(apr_pool_t *p)
{   /* code gets skipped if modules return a status code from
       their fixup hooks, so be sure to run REALLY first. See:
       http://svn.apache.org/viewvc?view=revision&revision=1154620
    */
    ap_hook_fixups( hook, NULL, NULL, APR_HOOK_REALLY_FIRST );
}


module AP_MODULE_DECLARE_DATA querystring2cookie_module = {
    STANDARD20_MODULE_STUFF,
    init_settings,              /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server configs */
    commands,                   /* command apr_table_t */
    register_hooks              /* register hooks */
};


