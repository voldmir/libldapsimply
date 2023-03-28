
Библиотека создана для простых операций с LDAP, добавление, удаление,
 переименование, изменение объектов в каталоге с авторизацией по протоколу Kerberos.

# Сборка для ALT Linux P9

cd ~/
mkdir build && cd build

wget https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-2.4.59.tgz

tar xvzf openldap-2.4.59.tgz && cd openldap-2.4.59

apt-get update

apt-get install sdf libsasl2-devel libunixODBC-devel perl-devel libopenslp-devel libkrb5-devel -y
apt-get install chrooted groff-base libdb4.7-devel libltdl-devel libssl-devel shtool libldap-devel -y
apt-get install gcc -y
apt-get install git -y

./configure --enable-syslog --enable-proctitle \
--enable-dynamic --with-tls=openssl --with-threads \
--enable-slapd --enable-lmpasswd --enable-crypt \
--enable-cleartext --enable-modules --enable-rewrite \
--enable-bdb=mod --enable-hdb=mod --enable-dnssrv=mod \
--enable-ldap=mod --enable-relay=mod --enable-memberof=mod \
--enable-meta=mod --enable-monitor=mod --enable-null=mod \
--enable-passwd=mod --with-yielding-select --enable-aci \
--disable-slapi --enable-slp --disable-shell --with-threads \
--enable-sql=mod --with-cyrus-sasl --enable-spasswd \
--enable-perl=mod --enable-accesslog=mod --enable-auditlog=mod \
--enable-dyngroup=mod --enable-dynlist=mod --enable-ppolicy=mod \
--enable-proxycache=mod --enable-refint=mod --enable-retcode=mod \
--enable-rwm=mod --enable-syncprov=mod --enable-translucent=mod \
--enable-unique=mod --enable-valsort=mod --disable-libtool-lock

cd ../

git clone https://github.com/voldmir/libldapsimply.git

cd libldapsimply

cp ../openldap-2.4.59/include/ldap_config.hin ../openldap-2.4.59/include/ldap_config.h

make && make install

при разработке использовался исходный код библиотек openldap-2.4.59 и krb5-1.17.2

# Пример использования:

```c
#include <stdio.h>
#include <stdlib.h>
#include "ldap.h"
#include <string.h>
#include "libldapsimply.h"

void iterr(char *dn, char *attr, char *val, int not_printable);
void search(LDAP *ld, char *attr, char *base, char *filter);
void delete(LDAP *ld, char *dn);
void renames(LDAP *ld, char *dn, char *new_rdn, char *new_parent);
void modifys(LDAP *ld, const char *dn, char *mods, int newentry);

static char *prep_dn = NULL;
static char *error_msg = NULL;

int main()
{
    int rc;
    LDAP *ld = NULL;
    
    char *ccache = "/tmp/.private/_foreman/EduRsbk5kclECl-_XxiTiw",
         *login = "testldap@SKF.LOC",
         *passwd = "Passw0rd?" /* NULL */,
         *client_keytab = NULL/* "/opt/stats/stats.keytab" */,
         *ldapuri = "ldap://dc1.skf.loc";

     rc = ccache_init_krb5_tgt(login, passwd, client_keytab, &ccache, &error_msg);
    if (rc != 0)
    {
        fprintf(stderr, "ccache_init_krb5_tgt is error (%d): %s\n", rc, error_msg);
        exit(1);
    }

    setenv("KRB5CCNAME", ccache, 1);

    printf("ccache: %s\n", ccache);

    rc = tool_conn_setup(&ld, ldapuri);
    if (ld == NULL)
    {
        fprintf(stderr, "tool_conn_setup: dont setup link");
        exit(1);
    }
    printf("tool_conn_setup is OK\n");

    rc = tool_bind(ld, &error_msg);
    if (rc != 0)
    {
        fprintf(stderr, "tool_bind: (%d), %s\n", rc, error_msg);
        exit(1);
    }
    printf("tool_bind is OK\n");

    char *attr = "sAMAccountName,distinguishedName,name,groupType,member";
    char *base = "ou=test,dc=skf,dc=loc";
    char *filter = "(objectClass=group)";

    search(ld, attr, base, filter);

    modifys(ld, "cn=qqqw,ou=test,dc=skf,dc=loc",
            "objectClass: group;objectClass: top;cn: qqqw;instanceType: 4;name: qqqw;sAMAccountName: qqqw",
            1);

    search(ld, attr, base, filter);

    /* "-2147483646" Глобальная*/
    /* "-2147483640" Универсальная*/
    /* "-2147483644" Локальная*/
    modifys(ld, "cn=qqqw,ou=test,dc=skf,dc=loc",
            "groupType: -2147483640",
            0);
    search(ld, attr, base, filter);
    renames(ld, "cn=qqqw,ou=test,dc=skf,dc=loc", "cn=qqqwwww", NULL);
    search(ld, attr, base, filter);
    delete (ld, "cn=qqqwwww,ou=skf,dc=arm,dc=loc");
    search(ld, attr, base, filter);
    tool_unbind(ld);

    rc = ccache_krb5_clean(ccache, &error_msg);
    if (rc != 0)
    {
        fprintf(stderr, "ccache_clean is error(%d): %s\n", rc, error_msg);
        return 1;
    }
    printf("ccache_clean is OK\n");

}

void iterr(char *dn, char *attr, char *val, int not_printable)
{
    if (prep_dn == NULL)
    {
        prep_dn = (char *)malloc(1);
    }

    if (strcasecmp(prep_dn, dn) != 0)
    {
        prep_dn = (char *)realloc(prep_dn, (strlen(dn) + 1) * sizeof(char));
        strcpy(prep_dn, dn);
        printf("dn: %s\n", dn);
    }
    printf("\t\t%s: %s\n", attr, val);
}

void search(LDAP *ld, char *attr, char *base, char *filter)
{
    char *error_msg = NULL;

    int rc = tool_search(
        ld,
        base,
        filter,
        attr,
        -1,
        &error_msg,
        iterr);
    if (rc != 0)
    {
        fprintf(stderr, "tool_search: (%d), %s\n", rc, error_msg);
        tool_unbind(ld);
        exit(1);
    }

    printf("tool_search is OK\n");
}

void delete(LDAP *ld, char *dn)
{
    int rc = tool_delete(ld, dn, &error_msg);
    if (rc != 0)
    {
        fprintf(stderr, "tool_delete: (%d), %s\n", rc, error_msg);
        if (rc != LDAP_NO_SUCH_OBJECT)
        {
            tool_unbind(ld);
            exit(1);
        }
    }

    printf("tool_delete is OK\n");
}

void renames(LDAP *ld, char *dn, char *new_rdn, char *new_parent)
{
    int rc = tool_rename(ld,
                         dn,
                         new_rdn,
                         new_parent,
                         &error_msg);
    if (rc != 0)
    {
        fprintf(stderr, "tool_rename: (%d), %s\n", rc, error_msg);
        tool_unbind(ld);
        exit(1);
    }

    printf("tool_rename is OK\n");
}

void modifys(LDAP *ld, const char *dn, char *mods, int newentry)
{
    int rc = tool_modify(ld, dn, mods, newentry, &error_msg, ";");
    if (rc != 0)
    {
        fprintf(stderr, "tool_modify: (%d), %s\n", rc, error_msg);
        tool_unbind(ld);
        exit(1);
    }

    printf("tool_modify: (%s) is OK\n", newentry ? "Add" : "Edit");
}

```

