#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include "ldap.h"
#include <string.h>
#include "libldapsimply.h"
#include "lber_pvt.h"
#include "ldif.h"

LDAPMod **strings_to_mods(char *attrs, int newentry, char *delim);

int tool_modify(LDAP *ld, const char *dn, char *mods, int newentry, char **error_msg, char *delim)
{
    int op;
    LDAPMod **pmods;
    int rc, i, j;

    if (dn == NULL)
    {
        error_to_str(LDAP_INVALID_DN_SYNTAX, error_msg);
        return (LDAP_INVALID_DN_SYNTAX);
    }

    pmods = strings_to_mods(mods, newentry == 1 ? LDAP_MOD_ADD : LDAP_MOD_REPLACE, delim);

    if (pmods == NULL)
    {
        error_to_str(LDAP_NAMING_VIOLATION, error_msg);
        return LDAP_NAMING_VIOLATION;
    }
    else
    {
        for (i = 0; pmods[i] != NULL; ++i)
        {

            op = pmods[i]->mod_op & ~LDAP_MOD_BVALUES;
            if (op == LDAP_MOD_ADD && (pmods[i]->mod_bvalues == NULL))
            {
                error_to_str(LDAP_OPERATIONS_ERROR, error_msg);
                return LDAP_OPERATIONS_ERROR;
            }
        }
    }

    int msgid;
    if (newentry)
    {
        rc = ldap_add_ext(ld, dn, pmods, NULL, NULL, &msgid);
    }
    else
    {
        rc = ldap_modify_ext(ld, dn, pmods, NULL, NULL, &msgid);
    }

    if (rc != LDAP_SUCCESS)
    {
        error_to_str(rc, error_msg);
        goto done;
    }
    rc = process_response(ld, msgid,
                          newentry ? LDAP_RES_ADD : LDAP_RES_MODIFY, error_msg);

done:
    if (pmods != NULL)
    {
        ber_memfree(pmods);
    }

    return rc;
}

LDAPMod **strings_to_mods(char *attrs, int newentry, char *delim)
{
    LDAPMod **mods;
    int num_mods = 0;
    int rc, i;
    struct berval btype, *bval;
    char *temp;
    char *_delim = "\n";

    if (delim)
    {
        _delim = delim;
    }

    temp = ber_memalloc(sizeof(char) * strlen(attrs) + 1);
    strcpy(temp, attrs);

    mods = (LDAPMod **)ber_memcalloc(1, sizeof(LDAPMod *));
    if (!mods)
    {
        goto failed;
    }
    mods[0] = NULL;

    char *line = strtok(temp, _delim);

    while (line != NULL)
    {
        bval = ber_memalloc(sizeof(struct berval *));
        if ((rc = ldif_parse_line2(line, &btype, bval, NULL)) < 0)
        {
            rc = LDAP_PARAM_ERROR;
            goto failed;
        }

        for (i = 0; mods[i] != NULL; ++i)
        {
            if ((btype.bv_len == strlen(mods[i]->mod_type) && 0 == strcasecmp(btype.bv_val, mods[i]->mod_type)))
            {
                ber_bvarray_add(mods[i]->mod_bvalues, bval);
                goto next;
            }
        }

        mods = (LDAPMod **)ber_memrealloc(mods, sizeof(LDAPMod *) * (num_mods + 2));

        mods[num_mods] = (LDAPMod *)ber_memcalloc(1, sizeof(LDAPMod));
        if (!mods[num_mods])
        {
            goto failed;
        }

        mods[num_mods]->mod_bvalues = (struct berval **)ber_memcalloc(1, sizeof(struct berval *));
        if (!mods[num_mods]->mod_bvalues)
        {
            goto failed;
        }

        ber_bvarray_add(mods[num_mods]->mod_bvalues, bval);
        mods[num_mods]->mod_type = btype.bv_val;
        mods[num_mods]->mod_op = newentry | LDAP_MOD_BVALUES;
        mods[num_mods + 1] = NULL;
        num_mods++;
    next:
        line = strtok(NULL, _delim);
    }

    return mods;

failed:
    if (mods)
    {
        for (i = 0; mods[i] != NULL && (mods[i]->mod_bvalues) != NULL; i++)
        {
            ber_bvarray_free(*(mods[i]->mod_bvalues));
        }
        ber_memfree(mods);
    }
    if (temp)
    {
        free(temp);
    }
    return NULL;
}
