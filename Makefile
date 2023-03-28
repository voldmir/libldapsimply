.PHONY: all build prep

all: build

LIBLDAP = ../openldap-2.4.59
BUILDDIR = ./build

prep:
		mkdir -p $(BUILDDIR)

base64.o:	$(LIBLDAP)/libraries/liblutil/base64.c
		gcc -c -fPIC  $(LIBLDAP)/libraries/liblutil/base64.c -I $(LIBLDAP)/include/ -I ./include/ -o  $(BUILDDIR)/base64.o

signal.o:	$(LIBLDAP)/libraries/liblutil/signal.c
		gcc -c -fPIC  $(LIBLDAP)/libraries/liblutil/signal.c -I $(LIBLDAP)/include/ -I ./include/ -o  $(BUILDDIR)/signal.o

getpass.o: $(LIBLDAP)/libraries/liblutil/getpass.c
		gcc -c -fPIC  $(LIBLDAP)/libraries/liblutil/getpass.c -I $(LIBLDAP)/include/ -I ./include/ -o  $(BUILDDIR)/getpass.o

sasl.o: $(LIBLDAP)/libraries/liblutil/sasl.c
		gcc -c -fPIC  $(LIBLDAP)/libraries/liblutil/sasl.c -I $(LIBLDAP)/include/ -I ./include/ -o  $(BUILDDIR)/sasl.o

common.o: common.c
		gcc -c -fPIC common.c -I $(LIBLDAP)/include/ -I $(LIBLDAP)/libraries/liblber/ -o  $(BUILDDIR)/common.o

tool_conn_setup.o: tool_conn_setup.c
		gcc -c -fPIC tool_conn_setup.c -I $(LIBLDAP)/include/ -I $(LIBLDAP)/libraries/liblber/ -o  $(BUILDDIR)/tool_conn_setup.o

tool_bind.o: tool_bind.c
		gcc -c -fPIC tool_bind.c -I $(LIBLDAP)/include/ -I $(LIBLDAP)/libraries/liblber/ -o  $(BUILDDIR)/tool_bind.o

tool_search.o: tool_search.c
		gcc -c -fPIC tool_search.c -I $(LIBLDAP)/include/ -I $(LIBLDAP)/libraries/liblber/ -o  $(BUILDDIR)/tool_search.o

tool_delete.o: tool_delete.c
		gcc -c -fPIC tool_delete.c -I $(LIBLDAP)/include/ -I $(LIBLDAP)/libraries/liblber/ -o  $(BUILDDIR)/tool_delete.o

tool_modify.o: tool_modify.c
		gcc -c -fPIC tool_modify.c -I $(LIBLDAP)/include/ -I $(LIBLDAP)/libraries/liblber/ -o  $(BUILDDIR)/tool_modify.o

tool_rename.o: tool_rename.c
		gcc -c -fPIC tool_rename.c -I $(LIBLDAP)/include/ -I $(LIBLDAP)/libraries/liblber/ -o  $(BUILDDIR)/tool_rename.o

tool_unbind.o: tool_unbind.c
		gcc -c -fPIC tool_unbind.c -I $(LIBLDAP)/include/ -I $(LIBLDAP)/libraries/liblber/ -o  $(BUILDDIR)/tool_unbind.o

krb5.o: krb5.c
		gcc -c -fPIC krb5.c -I $(LIBLDAP)/include/ -I $(LIBLDAP)/libraries/liblber/ -o  $(BUILDDIR)/krb5.o

build:	prep base64.o signal.o getpass.o sasl.o	common.o krb5.o tool_conn_setup.o tool_bind.o tool_search.o tool_delete.o tool_modify.o tool_rename.o tool_unbind.o
		gcc -shared -o libldapsimply.so  $(BUILDDIR)/*.o -lldap -llber -DHAVE_GETPASSPHRASE

clean:
		rm -fr $(BUILDDIR)
		rm -f test test.o

install:
		install -b libldapsimply.so /usr/lib64/
		@ldconfig -X

remove:
		rm -f /usr/lib64/libldapsimply.so
		@ldconfig -X


