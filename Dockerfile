FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[otlp]" "psycopg[binary]" boto3

# otlp extra: the gateway must decode the .NET OpenAgent platform's default
# http/protobuf export; without it only http/json ingest works.
EXPOSE 8100 8101 8102
CMD ["uvicorn", "openagent_audit.services.audit_api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8100"]
