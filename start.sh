#!/bin/sh

# Wait for PostgreSQL to be fully ready and database to be created
sleep 5

# Run database migrations
alembic upgrade head

# Start the application
uvicorn main:app --host 0.0.0.0 --port 80