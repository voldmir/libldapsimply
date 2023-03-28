#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "ldap.h"
#include "libldapsimply.h"
#include "lutil.h"
#include "ldif.h"

void get_entry(LDAP *ld, LDAPMessage *entry, LDAP_RESULT_INTERACT_PROC *interact);
int char_array_add(char ***a, char *el);
void char_array_free(char **a);
int char_array_from_string(char ***a, char *str, char *delim);
char *trim(char *s);

int tool_search(
    LDAP *ld,
    char *base,
    char *filtpatt,
    char *attributes,
    int sizelimit,
    char **error_msg,
    LDAP_RESULT_INTERACT_PROC *interact)
{
    int rc, rc2 = 0;
    LDAPMessage *msg, *res = NULL;
    ber_int_t msgid;
    struct timeval *tvp = NULL;
    struct timeval *tv_timelimitp = NULL;
    char **attrs = NULL;

    if (!interact)
    {
        error_to_str(LDAP_OPERATIONS_ERROR, error_msg);
        return (LDAP_OPERATIONS_ERROR);
    }

    if (attributes)
    {
        char_array_from_string(&attrs, attributes, ",");
    }

    rc = ldap_search_ext(ld, base, LDAP_SCOPE_SUBTREE, filtpatt, attrs, 0,
                         NULL, NULL, tv_timelimitp, sizelimit, &msgid);

    if (attrs)
    {
        char_array_free(attrs);
    }

    if (rc != LDAP_SUCCESS)
    {
        error_to_str(rc, error_msg);
        return (rc);
    }

    while ((rc = ldap_result(ld, LDAP_RES_ANY, LDAP_MSG_ONE, tvp, &res)) > 0)
    {

        for (msg = ldap_first_message(ld, res);
             msg != NULL;
             msg = ldap_next_message(ld, msg))
        {
            switch (ldap_msgtype(msg))
            {
            case LDAP_RES_SEARCH_ENTRY:
            {
                get_entry(ld, msg, interact);
                break;
            }
            case LDAP_RES_SEARCH_RESULT:
            {
                int err;
                rc2 = ldap_parse_result(ld, msg, &err, NULL, error_msg, NULL, NULL, 0);

                if (rc2 == LDAP_SUCCESS || err != LDAP_NO_RESULTS_RETURNED)
                    rc2 = err;

                if (*error_msg == NULL && rc2 != LDAP_SUCCESS)
                    error_to_str(rc2, error_msg);

                goto done;
            }
            }
        }

        ldap_msgfree(res);
        fflush(stdout);
    }

done:
    if (tvp == NULL && rc != LDAP_RES_SEARCH_RESULT)
    {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, (void *)&rc2);
    }

    ldap_msgfree(res);
    return (rc2);
}

void get_entry(LDAP *ld, LDAPMessage *entry, LDAP_RESULT_INTERACT_PROC *interact)
{

    int i, rc;
    BerElement *ber = NULL;
    BerVarray bvals, *bvp = &bvals;
    BerValue bv;
    int res;
    char *dn;

    rc = ldap_get_dn_ber(ld, entry, &ber, &bv);
    dn = bv.bv_val;

    for (rc = ldap_get_attribute_ber(ld, entry, ber, &bv, bvp);
         rc == LDAP_SUCCESS;
         rc = ldap_get_attribute_ber(ld, entry, ber, &bv, bvp))
    {
        if (bv.bv_val == NULL)
            break;
        if (bvals)
        {
            for (i = 0; bvals[i].bv_val != NULL; i++)
            {

                if (interact)
                {
                    int k = ldif_is_not_printable(bvals[i].bv_val, bvals[i].bv_len);

                    if (k)
                    {
                        struct berval bv64;
                        bv64.bv_len = LUTIL_BASE64_ENCODE_LEN(bvals[i].bv_len) + 1;
                        bv64.bv_val = ber_memalloc(bv64.bv_len + 1);
                        bv64.bv_len = lutil_b64_ntop((unsigned char *)bvals[i].bv_val, bvals[i].bv_len, bv64.bv_val, bv64.bv_len);
                        (interact)(dn, bv.bv_val, bv64.bv_val, k);
                        ber_memfree(bv64.bv_val);
                    }
                    else
                    {
                        (interact)(dn, bv.bv_val, bvals[i].bv_val, k);
                    }
                }
            }
            ber_memfree(bvals);
        }
    }
    if (ber != NULL)
    {
        ber_free(ber, 0);
    }
}

int char_array_add(char ***a, char *el)
{
    int n;

    if (*a == NULL)
    {
        if (el == NULL)
        {
            return 0;
        }
        n = 0;

        *a = (char **)malloc(2 * sizeof(char *));
        if (*a == NULL)
        {
            return -1;
        }
    }
    else
    {
        for (n = 0; *a != NULL && (*a)[n] != NULL; n++)
        {
            ;
        }
        if (el == NULL)
        {
            return n;
        }

        *a = (char **)realloc(*a, (n + 2) * sizeof(char *));

        if (aligned_alloc == NULL)
        {
            return -1;
        }
    }

    (*a)[n] = (char *)malloc(sizeof(char) * strlen(el) + 1);
    strcpy((*a)[n], el);
    (*a)[++n] = NULL;

    return n;
}

void char_array_free(char **a)
{
    int n;
    if (a != NULL)
    {
        for (n = 0; a != NULL && (a)[n] != NULL; n++)
        {
            free((a)[n]);
        }
    }
}

int char_array_from_string(char ***a, char *str, char *delim)
{
    int n;
    if (*a != NULL)
    {
        char_array_free(*a);
    }

    char *temp = malloc(sizeof(char) * strlen(str) + 1);
    strcpy(temp, str);
    char *t, *line = strtok(temp, delim);
    while (line != NULL)
    {
        t = trim(line);
        n = char_array_add(a, t);
        if (n == -1)
        {
            goto failed;
        }
        line = strtok(NULL, delim);
    }
failed:
    if (temp)
    {
        free(temp);
    }
    return n;
}

char *ltrim(char *s)
{
    while (isspace(*s))
        s++;
    return s;
}

char *rtrim(char *s)
{
    char *back = s + strlen(s);
    while (isspace(*--back))
        ;
    *(back + 1) = '\0';
    return s;
}

char *trim(char *s)
{
    return rtrim(ltrim(s));
}
