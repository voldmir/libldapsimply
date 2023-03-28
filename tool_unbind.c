#include <sasl/sasl.h>
#include "ldap.h"

void tool_unbind(LDAP *ld)
{
    if (ld != NULL)
    {
        (void)ldap_set_option(ld, LDAP_OPT_SERVER_CONTROLS, NULL);
        (void)ldap_unbind_ext(ld, NULL, NULL);
    }
    sasl_done();
}
