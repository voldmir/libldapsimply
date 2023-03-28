#include <stdlib.h>
#include "ldap.h"

void error_to_str(int errcode, char **error_msg)
{
    if (error_msg != NULL)
    {
        ber_memfree(*error_msg);
        *error_msg = ber_strdup(ldap_err2string(errcode));
    }
}

int process_response(LDAP *ld, int msgid, int op, char **error_msg)
{
    LDAPMessage *res;
    int rc = LDAP_OTHER, msgtype;
    struct timeval tv = {0, 0};
    int err;
    char *matched = NULL;

    for (;;)
    {
        tv.tv_sec = 0;
        tv.tv_usec = 100000;

        rc = ldap_result(ld, msgid, LDAP_MSG_ALL, &tv, &res);
        if (rc == -1)
        {
            ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
            return rc;
        }

        if (rc != 0)
        {
            break;
        }
    }

    msgtype = ldap_msgtype(res);

    rc = ldap_parse_result(ld, res, &err, &matched, error_msg, NULL, NULL, 1);
    if (rc == LDAP_SUCCESS)
        rc = err;

    if (msgtype != op)
        rc = LDAP_OTHER;

    if (matched)
        ldap_memfree(matched);

    return rc;
}
