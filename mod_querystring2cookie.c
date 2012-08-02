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

// XXX config values
#define COOKIE_EXPIRES 86400
#define COOKIE_KEY_PREFIX "kxe_"
#define COOKIE_MAX_SIZE 1024
#define COOKIE_DISABLE_IF_DNT 1
#define COOKIE_DOMAIN ".krxd.net"

module AP_MODULE_DECLARE_DATA querystring2cookie_module;

// See here for the structure of request_rec:
// http://ci.apache.org/projects/httpd/trunk/doxygen/structrequest__rec.html
static int hook(request_rec *r)
{
    _DEBUG && fprintf( stderr, "Query string: %s\n", r->args );

    // ***********************************
    // Calculate expiry time
    // ***********************************

    // The expiry time. We can't use max-age because IE6 - IE8 do not
    // support it :(
    apr_time_exp_t tms;
    apr_time_exp_gmt( &tms, r->request_time
                         + apr_time_from_sec( COOKIE_EXPIRES ) );

    char *expires = apr_psprintf( r->pool,
                        "expires=%s, %.2d-%s-%.2d %.2d:%.2d:%.2d GMT",
                        apr_day_snames[tms.tm_wday],
                        tms.tm_mday,
                        apr_month_snames[tms.tm_mon],
                        tms.tm_year % 100,
                        tms.tm_hour, tms.tm_min, tms.tm_sec
                    );

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

        // Does not contains a =, meaning it's garbage
        if( !strchr( pair, '=' ) ) {
            _DEBUG && fprintf( stderr, "invalid pair: %s\n", pair );

        // looks like a valid key=value declaration
        } else {

            _DEBUG && fprintf( stderr, "pair: %s\n", pair );

            int this_pair_size = strlen( COOKIE_KEY_PREFIX ) + strlen( pair );

            // Make sure the individual pair, as well as the whole thing doesn't
            // get too long
            if( (this_pair_size < COOKIE_MAX_SIZE) &&
                (total_pair_size + this_pair_size < COOKIE_MAX_SIZE)
            ) {

                // update the book keeping
                total_pair_size += this_pair_size;

                // And append it to the existing cookie
                char *cookie = apr_pstrcat( r->pool,
                                    COOKIE_KEY_PREFIX, pair, "; ",
                                    "path=/; ",
                                    "domain=", COOKIE_DOMAIN, "; ",
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
                    pair, this_pair_size, total_pair_size, COOKIE_MAX_SIZE );
            }
        }

        // And get the next pair
        pair = apr_strtok( NULL, "&", &last_pair );

    }

    return OK;
}

static void register_hooks(apr_pool_t *p)
{   /* code gets skipped if modules return a status code from
       their fixup hooks, so be sure to run REALLY first. See:
       http://svn.apache.org/viewvc?view=revision&revision=1154620
    */
    ap_hook_fixups( hook, NULL, NULL, APR_HOOK_REALLY_FIRST );
}


module AP_MODULE_DECLARE_DATA querystring2cookie_module = {
    STANDARD20_MODULE_STUFF,
    NULL, //make_querystring2cookie_settings,  /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server configs */
    NULL, //querystring2cookie_cmds,           /* command apr_table_t */
    register_hooks              /* register hooks */
};


