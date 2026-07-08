SHELL := /bin/bash

CC ?= cc
CFLAGS ?= -O2 -fPIC -Wall -Wextra -std=c99
LDFLAGS ?= -shared
LIBS ?= -lcrypto
MYSQL_CFLAGS ?= $(shell mysql_config --cflags 2>/dev/null)
UDF_SO = secure_db_fields_mysql.so
SRC = src/secure_db_fields_mysql.c src/secure_db_fields_core.c

MYSQL ?= mysql
MYSQL_DEFAULTS_FILE ?=
MYSQL_SOCKET ?=
CONFIRM ?=

.PHONY: help all abi57 verify doctor install enable disable status uninstall clean

help:
	@printf '%s\n' \
	  'SecureDBFields MySQL 5.7 deployment bundle' \
	  '' \
	  '  make verify' \
	  '  make doctor [MYSQL_DEFAULTS_FILE=/etc/mysql/admin.cnf] [MYSQL_SOCKET=/run/mysqld/mysqld.sock]' \
	  '  sudo make install [MYSQL_DEFAULTS_FILE=/etc/mysql/admin.cnf] [MYSQL_SOCKET=/run/mysqld/mysqld.sock]' \
	  '  make enable [MYSQL_DEFAULTS_FILE=/etc/mysql/admin.cnf] [MYSQL_SOCKET=/run/mysqld/mysqld.sock]' \
	  '  make status [MYSQL_DEFAULTS_FILE=/etc/mysql/admin.cnf] [MYSQL_SOCKET=/run/mysqld/mysqld.sock]' \
	  '  make disable CONFIRM=DISABLE_SECURE_DB_FIELDS [MYSQL_DEFAULTS_FILE=/etc/mysql/admin.cnf] [MYSQL_SOCKET=/run/mysqld/mysqld.sock]' \
	  '  sudo make uninstall CONFIRM=REMOVE_SECURE_DB_FIELDS [MYSQL_DEFAULTS_FILE=/etc/mysql/admin.cnf] [MYSQL_SOCKET=/run/mysqld/mysqld.sock]'

all: abi57

$(UDF_SO): $(SRC) src/secure_db_fields_core.h src/mysql_udf_abi_57.h
	$(CC) $(CFLAGS) $(MYSQL_CFLAGS) -Isrc $(LDFLAGS) -o $@ $(SRC) $(LIBS)

abi57: $(SRC) src/secure_db_fields_core.h src/mysql_udf_abi_57.h
	$(CC) $(CFLAGS) -DSDF_MYSQL_UDF_ABI_57 -Isrc $(LDFLAGS) -o $(UDF_SO) $(SRC) $(LIBS)

verify:
	./bin/verify

doctor:
	MYSQL_SOCKET="$(MYSQL_SOCKET)" ./bin/doctor --mysql "$(MYSQL)" $(if $(MYSQL_DEFAULTS_FILE),--defaults-extra-file "$(MYSQL_DEFAULTS_FILE)")

install: verify
	MYSQL_SOCKET="$(MYSQL_SOCKET)" ./bin/install --mysql "$(MYSQL)" $(if $(MYSQL_DEFAULTS_FILE),--defaults-extra-file "$(MYSQL_DEFAULTS_FILE)")

enable:
	MYSQL_SOCKET="$(MYSQL_SOCKET)" ./bin/enable --mysql "$(MYSQL)" $(if $(MYSQL_DEFAULTS_FILE),--defaults-extra-file "$(MYSQL_DEFAULTS_FILE)")

disable:
	@test "$(CONFIRM)" = "DISABLE_SECURE_DB_FIELDS" || { echo 'disable requires CONFIRM=DISABLE_SECURE_DB_FIELDS' >&2; exit 2; }
	MYSQL_SOCKET="$(MYSQL_SOCKET)" ./bin/disable --mysql "$(MYSQL)" $(if $(MYSQL_DEFAULTS_FILE),--defaults-extra-file "$(MYSQL_DEFAULTS_FILE)")

status:
	MYSQL_SOCKET="$(MYSQL_SOCKET)" ./bin/status --mysql "$(MYSQL)" $(if $(MYSQL_DEFAULTS_FILE),--defaults-extra-file "$(MYSQL_DEFAULTS_FILE)")

uninstall:
	@test "$(CONFIRM)" = "REMOVE_SECURE_DB_FIELDS" || { echo 'uninstall requires CONFIRM=REMOVE_SECURE_DB_FIELDS' >&2; exit 2; }
	MYSQL_SOCKET="$(MYSQL_SOCKET)" ./bin/uninstall --mysql "$(MYSQL)" $(if $(MYSQL_DEFAULTS_FILE),--defaults-extra-file "$(MYSQL_DEFAULTS_FILE)")

clean:
	rm -f $(UDF_SO) *.o src/*.o
