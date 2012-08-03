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

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"

#include <math.h>

/* ********************************************

    Structs & Defines

   ******************************************** */

#ifdef DEBUG                    // To print diagnostics to the error log
#define _DEBUG 1                // enable through gcc -DDEBUG
#else
#define _DEBUG 0
#endif

// module configuration - this is basically a global struct
typedef struct {
    int enabled;            // module enabled?
    int enabled_if_dnt;     // module enabled for requests with X-DNT?
    int cookie_expires;     // holds the expires value for the cookie
    int cookie_max_size;    // maximum size of all the key/value pairs
    char *cookie_domain;    // domain the cookie will be set in
    char *cookie_prefix;    // prefix all keys in the cookie with this string
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
    if( !(r->args || (strlen( r->args ) < 1)) ) {
        return DECLINED;
    }

    /* skip if dnt headers are present? */
    if( !(cfg->enabled_if_dnt) && apr_table_get( r->headers_in, "DNT" ) ) {
        _DEBUG && fprintf( stderr, "DNT header sent: declined\n" );
        return DECLINED;
    }

    _DEBUG && fprintf( stderr, "Query string: %s\n", r->args );

    // ***********************************
    // Calculate expiry time
    // ***********************************

    // The expiry time. We can't use max-age because IE6 - IE8 do not
    // support it :(
    apr_time_exp_t tms;
    apr_time_exp_gmt( &tms, r->request_time
                         + apr_time_from_sec( cfg->cookie_expires ) );

    // XXX add if cfg->expires
    char *expires = apr_psprintf( r->pool,
                        "expires=%s, %.2d-%s-%.2d %.2d:%.2d:%.2d GMT",
                        apr_day_snames[tms.tm_wday],
                        tms.tm_mday,
                        apr_month_snames[tms.tm_mon],
                        tms.tm_year % 100,
                        tms.tm_hour, tms.tm_min, tms.tm_sec
                    );

    // ***********************************
    // Domain to set the cookie in
    // ***********************************

    // If empty, the browser assign the domain the object was requested from
    char *domain = strlen( cfg->cookie_domain )
                    ? apr_pstrcat( r->pool, "domain=", cfg->cookie_domain, "; ", NULL )
                    : "";

    // ***********************************
    // Find key/value pairs
    // ***********************************

    // keep track of how much data we've been writing - there's a limit to how
    // much a browser will store per domain (usually 4k) so we want to make sure
    // it's not getting flooded.
    int total_pair_size = 0;

    // Iterate over the key/value pairs
    char *last_pair;
    char *pair = apr_strtok( apr_pstrdup( r->pool, r->args ), "&", &last_pair );

    // we need to build a Set-Cookie for EVERY pair - it is not supported to
    // send more than one key=val pair per set-cookie :(
    while( pair != NULL ) {

        // length of the substr before the = sign (or index of the = sign)
        int contains_equals_at = strcspn( pair, "=" );

        // Does not contains a =, or starts with a =, meaning it's garbage
        if( !strstr(pair, "=") || contains_equals_at < 1 ) {
            _DEBUG && fprintf( stderr, "invalid pair: %s\n", pair );

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

                _DEBUG && fprintf( stderr, "strlen ignore: %i, =: %i\n",
                        strlen(ignore ), contains_equals_at );

                if( strlen( ignore ) == contains_equals_at &&
                    strncasecmp( pair, ignore, contains_equals_at ) == 0
                ) {
                    _DEBUG && fprintf( stderr, "pair %s is on the ignore list: %s\n",
                                        pair, ignore );

                    // signal to continue the outer loop; we found an ignore match
                    do_continue = 1;
                    break;

                }
            }

            // match found, move on
            if( do_continue ) {
                // And get the next pair -- has to be done at every break
                pair = apr_strtok( NULL, "&", &last_pair );

                continue;
            }

        }

        // looks like a valid key=value declaration
        _DEBUG && fprintf( stderr, "pair: %s\n", pair );

        int this_pair_size = strlen( cfg->cookie_prefix ) + strlen( pair );

        // Make sure the individual pair, as well as the whole thing doesn't
        // get too long
        if( (this_pair_size <= cfg->cookie_max_size) &&
            (total_pair_size + this_pair_size <= cfg->cookie_max_size)
        ) {

            // update the book keeping
            total_pair_size += this_pair_size;

            // And append it to the existing cookie
            char *cookie = apr_pstrcat( r->pool,
                                cfg->cookie_prefix, pair, "; ",
                                "path=/; ",
                                domain,
                                expires,
                                NULL
                            );

            // r->err_headers_out also honors non-2xx responses and
            // internal redirects. See the patch here:
            // http://svn.apache.org/viewvc?view=revision&revision=1154620
            apr_table_addn( r->err_headers_out, "Set-Cookie", cookie );

            _DEBUG && fprintf( stderr, "cookie: %s\n", cookie );

        } else {
            _DEBUG && fprintf( stderr,
                "Pair size too long to add: %s (this: %i total: %i max: %i)\n",
                pair, this_pair_size, total_pair_size, cfg->cookie_max_size );
        }

        // and move the pointer
        pair = apr_strtok( NULL, "&", &last_pair );
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
    cfg->enabled           = 0;
    cfg->enabled_if_dnt    = 0;
    cfg->cookie_expires    = 86400; // a day
    cfg->cookie_max_size   = 1024;
    cfg->cookie_domain     = "";    // used in apr_pstrcat - can't be null
    cfg->cookie_prefix     = "";    // used in apr_pstrcat - can't be null
    cfg->qs_ignore         = apr_array_make(p, 2, sizeof(const char*) );

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

        cfg->cookie_domain = apr_pstrdup(cmd->pool, value);

    /* Prefix for all keys set in the cookie */
    } else if( strcasecmp(name, "QS2CookiePrefix") == 0 ) {
        cfg->cookie_prefix     = apr_pstrdup(cmd->pool, value);


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
    AP_INIT_TAKE1("QS2CookieExpires",       set_config_value,   NULL, OR_FILEINFO,
                  "expiry time for the cookie, in seconds after the request is served"),
    AP_INIT_TAKE1("QS2CookieDomain",        set_config_value,   NULL, OR_FILEINFO,
                  "domain to which this cookie applies"),
    AP_INIT_TAKE1("QS2CookieMaxSize",       set_config_value,   NULL, OR_FILEINFO,
                  "maximum size to allow for all the key/value pairs in this request"),
    AP_INIT_TAKE1("QS2CookiePrefix",        set_config_value,   NULL, OR_FILEINFO,
                  "prefix all cookie keys with this string"),
    AP_INIT_FLAG( "QS2CookieEnableIfDNT",  set_config_enable,  NULL, OR_FILEINFO,
                  "whether or not to enable cookies if 'X-DNT' header is present"),
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


