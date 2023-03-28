#include "ldap.h"
#include <sasl/sasl.h>
#include "libldapsimply.h"
#include "lutil_ldap.h"

int tool_bind(LDAP *ld, char **error_msg)
{
    int rc, msgid;
    LDAPMessage *result = NULL;
    char *sasl_mech = "GSSAPI";

    void *defaults = lutil_sasl_defaults(ld, sasl_mech, NULL, NULL, NULL, NULL);

    rc = ldap_sasl_interactive_bind_s(ld, NULL, sasl_mech, NULL,
                                      NULL, LDAP_SASL_QUIET, lutil_sasl_interact, defaults);

    lutil_sasl_freedefs(defaults);

    if (rc != LDAP_SUCCESS)
    {
        error_to_str(rc, error_msg);
    }

    return rc;
}
