CC ?= cc
CFLAGS ?= -O2 -fPIC -Wall -Wextra -Wformat -Wformat-security -fstack-protector-strong -D_FORTIFY_SOURCE=2 -std=c99
LDFLAGS ?= -shared
LIBS ?= -lcrypto
MYSQL_CFLAGS ?= $(shell mysql_config --cflags 2>/dev/null)
MYSQL_LIBDIR ?= $(shell mysql_config --plugindir 2>/dev/null)

SRC = src/secure_db_fields_mysql.c ../ext/secure_db_fields/secure_db_fields_core.c
OUT = secure_db_fields_mysql.so

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) $(MYSQL_CFLAGS) -I../ext/secure_db_fields -Isrc $(LDFLAGS) -o $@ $(SRC) $(LIBS)

abi57:
	$(CC) $(CFLAGS) -DSDF_MYSQL_UDF_ABI_57 -I../ext/secure_db_fields -Isrc $(LDFLAGS) -o $(OUT) $(SRC) $(LIBS)

install: $(OUT)
	@if [ -z "$(MYSQL_LIBDIR)" ]; then echo "mysql_config --plugindir failed"; exit 1; fi
	install -m 0755 $(OUT) $(MYSQL_LIBDIR)/$(OUT)

clean:
	rm -f $(OUT) *.o
.PHONY: all abi57 install clean
