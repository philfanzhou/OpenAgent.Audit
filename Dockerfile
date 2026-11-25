FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
# The console SPA is served by audit-api itself; without this line the image
# depends on a bind mount of frontend/dist and returns 404 for every page.
COPY frontend/dist ./frontend/dist
RUN pip install --no-cache-dir ".[otlp]" "psycopg[binary]" boto3

# otlp extra: the gateway must decode the .NET OpenAgent platform's default
# http/protobuf export; without it only http/json ingest works.
EXPOSE 8100 8101 8102
CMD ["uvicorn", "openagent_audit.services.audit_api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8100"]
