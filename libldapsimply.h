#ifndef _LIBLDAPTOOLS_H_
#define _LIBLDAPTOOLS_H_
typedef void(LDAP_RESULT_INTERACT_PROC)(char *dn, char *attr, char *val, int not_printable);

int tool_conn_setup(LDAP **ld, char *ldapuri);
int tool_bind(LDAP *ldd, char **error_msg);
int tool_search(LDAP *ld,
                char *base,
                char *filtpatt,
                char *attributes,
                int sizelimit,
                char **error_msg,
                LDAP_RESULT_INTERACT_PROC *interact);

int tool_delete(LDAP *ld, const char *dn, char **error_msg);
int tool_modify(LDAP *ld, const char *dn, char *mods, int newentry, char **error_msg, char *delim);
int tool_rename(LDAP *ld, char *dn, char *new_rdn, char *new_parent, char **error_msg);
void tool_unbind(LDAP *ld);
/*krb5*/
int ccache_krb5_clean(char *cache_name, char **error_msg);
int ccache_init_krb5_tgt(char *principal_name, char *passwd, char *keytab_name, char **cache_name, char **error_msg);
/*common*/
void error_to_str(int errcode, char **error_msg);
int process_response(LDAP *ld, int msgid, int op, char **error_msg);

#endif /* _LIBLDAPTOOLS_H_ */