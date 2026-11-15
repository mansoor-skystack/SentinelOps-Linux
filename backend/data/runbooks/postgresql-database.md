# PostgreSQL & Cloud Database Connectivity Guide

## FATAL: password authentication failed / Connection Timed Out (Port 5432)
Occurs when `DATABASE_URL` credentials mismatch PostgreSQL `pg_hba.conf` rules, firewall blocks TCP `5432`, or `sslmode=require` is omitted for cloud PostgreSQL instances.

### Diagnostic Steps
```bash
pg_isready -h <db-host> -p 5432
```

### Resolution
Verify connection string with TLS (`sslmode=require`) and reload PostgreSQL:
```bash
psql "$DATABASE_URL" -c "SELECT version();"
```
