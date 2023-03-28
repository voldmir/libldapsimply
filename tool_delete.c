#include "ldap.h"
#include "libldapsimply.h"

int tool_delete(LDAP *ld, const char *dn, char **error_msg)
{
    int msgid, rc;

    rc = ldap_delete_ext(ld, dn, NULL, NULL, &msgid);
    if (rc != LDAP_SUCCESS)
    {
        error_to_str(rc, error_msg);
        goto cleanup;
    }
    rc = process_response(ld, msgid, LDAP_RES_DELETE, error_msg);

cleanup:
    return rc;
}
