#!/bin/bash
set -e

echo "Initializing PostgreSQL..."

# Create user if not exists
psql -v ON_ERROR_STOP=1 --username "postgres" --dbname "postgres" <<-EOSQL
    DO \$\$ BEGIN
        CREATE ROLE "$POSTGRES_USER" WITH LOGIN PASSWORD '$POSTGRES_PASSWORD';
    EXCEPTION WHEN DUPLICATE_OBJECT THEN
        ALTER ROLE "$POSTGRES_USER" WITH PASSWORD '$POSTGRES_PASSWORD';
    END \$\$;
EOSQL

echo "User $POSTGRES_USER ready"

# Create database if not exists
psql -v ON_ERROR_STOP=1 --username "postgres" --dbname "postgres" <<-EOSQL
    SELECT 'CREATE DATABASE $POSTGRES_DB OWNER $POSTGRES_USER' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$POSTGRES_DB')\gexec
EOSQL

echo "Database $POSTGRES_DB ready"
