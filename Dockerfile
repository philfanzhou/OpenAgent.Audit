FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . "psycopg[binary]" boto3

EXPOSE 8100 8101
CMD ["uvicorn", "openagent_audit.services.audit_api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8100"]
