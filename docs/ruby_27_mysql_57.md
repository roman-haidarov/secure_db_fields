# Ruby 2.7.1 + MySQL 5.7 compatibility notes

This package targets Ruby `>= 2.7.1` and MySQL `5.7`.

## Ruby

The Ruby layer intentionally avoids Ruby 3-only constructs:

- no `Data.define`;
- no endless methods;
- no pattern matching dependency;
- no anonymous argument forwarding (`...`);
- no Ruby 3-only keyword-argument behavior assumptions.

The native extension uses the stable Ruby C API available in Ruby 2.7.

## MySQL 5.7

The MySQL layer intentionally avoids MySQL 8-only features:

- no functional indexes;
- no generated columns backed by stored/loadable functions;
- bidx/search tokens are physical `BINARY(32)` columns;
- admin search uses stored procedures/query templates with `WHERE *_bidx = secure_*_bidx(...)`.

The `mysql_udf/src/mysql_udf_abi_57.h` shim lets the UDF source compile in a MySQL 5.7-compatible ABI mode when headers are not present:

```bash
cd mysql_udf
make abi57
```

A live MySQL 5.7 server is still required for integration testing and `CREATE FUNCTION` installation.
