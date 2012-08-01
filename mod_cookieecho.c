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

module AP_MODULE_DECLARE_DATA cookieecho_module;

static int hook(request_rec *r)
{
    _DEBUG && fprintf( stderr, "In hook\n" );

    return OK;
}

static void register_hooks(apr_pool_t *p)
{   /* code gets skipped if modules return a status code from
       their fixup hooks, so be sure to run REALLY first. See:
       http://svn.apache.org/viewvc?view=revision&revision=1154620
    */
    ap_hook_fixups( hook, NULL, NULL, APR_HOOK_REALLY_FIRST );
}


module AP_MODULE_DECLARE_DATA cookieecho_module = {
    STANDARD20_MODULE_STUFF,
    NULL, //make_cookieecho_settings,  /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server configs */
    NULL, //cookieecho_cmds,           /* command apr_table_t */
    register_hooks              /* register hooks */
};


