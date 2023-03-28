#include "portable.h"
#include "ldap.h"
#include "libldapsimply.h"

int tool_conn_setup(LDAP **ld, char *ldapuri)
{
    int rc;

    if (ldapuri != NULL)
    {
        LDAPURLDesc *lud;
        rc = ldap_url_parse(ldapuri, &lud);

        if (rc != LDAP_URL_SUCCESS)
        {
            return LDAP_URL_ERR_PARAM;
        }
        ldapuri = ldap_url_desc2str(lud);
        ldap_free_urldesc(lud);
    }

    rc = ldap_initialize(ld, ldapuri);
    if (rc != LDAP_SUCCESS)
    {
        return rc;
    }

    if (ldap_set_option(*ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF) != LDAP_OPT_SUCCESS)
    {
        return LDAP_LOCAL_ERROR;
    }

    int protocol = 3;
    if (ldap_set_option(*ld, LDAP_OPT_PROTOCOL_VERSION, &protocol) != LDAP_OPT_SUCCESS)
    {
        return LDAP_LOCAL_ERROR;
    }

    return LDAP_OPT_SUCCESS;
}
