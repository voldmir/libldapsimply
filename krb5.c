#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <krb5.h>

void krb5_error_to_str(int errcode, char **error_msg)
{
    if (error_msg != NULL)
    {
        const char *str = error_message(errcode);
        *error_msg = realloc(*error_msg, sizeof(char) * strlen(str) + 1);
        strcpy(*error_msg, str);
    }
}

int ccache_krb5_clean(char *cache_name, char **error_msg)
{
    krb5_context context;
    krb5_ccache cache = NULL;
    krb5_cccol_cursor cursor;
    int ret;

    ret = krb5_init_context(&context);
    if (ret)
        goto cleanup;

    ret = krb5_cc_set_default_name(context, cache_name);
    if (ret)
        goto cleanup;

    ret = krb5_cccol_cursor_new(context, &cursor);
    if (ret)
        goto cleanup;

    while (krb5_cccol_cursor_next(context, cursor, &cache) == 0 &&
           cache != NULL)
    {
        ret = krb5_cc_get_full_name(context, cache, &cache_name);
        if (ret)
            goto cleanup;

        ret = krb5_cc_destroy(context, cache);
        krb5_free_string(context, cache_name);
    }
cleanup:
    krb5_cccol_cursor_free(context, &cursor);
    krb5_free_context(context);

    if (ret)
        krb5_error_to_str(ret, error_msg);

    return ret;
}

int ccache_init_krb5_tgt(char *principal_name, char *passwd, char *keytab_name, char **cache_name, char **error_msg)
{
    krb5_context context;
    int ret;
    krb5_principal me;
    krb5_creds my_creds;
    krb5_keytab keytab = 0;
    krb5_get_init_creds_opt *options = NULL;
    krb5_ccache out_cc = NULL;

    if (principal_name == NULL ||
        (passwd == NULL && keytab_name == NULL) ||
        cache_name == NULL || error_msg == NULL)
    {
        ret = KRB5_LIBOS_CANTREADPWD;
        goto end;
    }

    ret = krb5_init_context(&context);
    if (ret)
        goto end;

    ret = krb5_cc_new_unique(context, "FILE", NULL, &out_cc);
    if (ret)
        goto cleanup;

    ret = krb5_cc_get_full_name(context, out_cc, cache_name);
    if (ret)
        goto cleanup;

    ret = krb5_parse_name_flags(context, principal_name, 0, &me);
    if (ret)
        goto cleanup;

    memset(&my_creds, 0, sizeof(my_creds));

    ret = krb5_get_init_creds_opt_alloc(context, &options);
    if (ret)
        goto cleanup;

    ret = krb5_get_init_creds_opt_set_out_ccache(context, options, out_cc);
    if (ret)
        goto cleanup;

    if (passwd == NULL)
    {
        ret = krb5_kt_resolve(context, keytab_name, &keytab);
        if (ret)
            goto cleanup;

        ret = krb5_get_init_creds_keytab(context, &my_creds, me, keytab, 0, NULL, options);
    }
    else
    {
        ret = krb5_get_init_creds_password(context, &my_creds, me, passwd, NULL, NULL, 0, NULL, options);
    }

    if (ret)
        goto cleanup;

cleanup:
    if (options)
        krb5_get_init_creds_opt_free(context, options);
    if (out_cc != NULL)
        krb5_cc_close(context, out_cc);
    krb5_free_principal(context, me);
    krb5_free_cred_contents(context, &my_creds);
    if (keytab != NULL)
        krb5_kt_close(context, keytab);
    krb5_free_context(context);
end:
    if (ret)
        krb5_error_to_str(ret, error_msg);

    return ret;
}