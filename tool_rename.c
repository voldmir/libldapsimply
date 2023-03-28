#include <stdlib.h>
#include "ldap.h"
#include "libldapsimply.h"

int tool_rename(LDAP *ld, char *dn, char *new_rdn, char *new_parent, char **error_msg)
{
    int rc, msgid;

    rc = ldap_rename(ld, dn, new_rdn, new_parent, 1, NULL, NULL, &msgid);
    if (rc != LDAP_SUCCESS)
    {
        error_to_str(rc, error_msg);
        goto done;
    }
    rc = process_response(ld, msgid, LDAP_RES_RENAME, error_msg);
done:
    return rc;
}