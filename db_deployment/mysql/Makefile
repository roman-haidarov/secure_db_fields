CC ?= cc
CFLAGS ?= -O2 -fPIC -Wall -Wextra -std=c99
LDFLAGS ?= -shared
LIBS ?= -lcrypto
MYSQL_CFLAGS ?= $(shell mysql_config --cflags 2>/dev/null)
MYSQL_PLUGIN_DIR ?= $(shell mysql_config --plugindir 2>/dev/null)
UDF_SO = secure_db_fields_mysql.so
SRC = src/secure_db_fields_mysql.c src/secure_db_fields_core.c

.PHONY: all abi57 verify doctor install enable disable status uninstall clean

all: $(UDF_SO)

$(UDF_SO): $(SRC) src/secure_db_fields_core.h src/mysql_udf_abi_57.h
	$(CC) $(CFLAGS) $(MYSQL_CFLAGS) -Isrc $(LDFLAGS) -o $@ $(SRC) $(LIBS)

abi57:
	$(CC) $(CFLAGS) -DSDF_MYSQL_UDF_ABI_57 -Isrc $(LDFLAGS) -o $(UDF_SO) $(SRC) $(LIBS)

verify:
	@bin/verify

doctor:
	@bin/doctor

install:
	@bin/install

enable:
	@bin/enable

disable:
	@bin/disable

status:
	@bin/status

uninstall:
	@bin/uninstall

clean:
	rm -f $(UDF_SO) *.o src/*.o
