FROM python:3.12-slim

WORKDIR /app

# Copy all source first so pip install can find the app package
COPY pyproject.toml .
COPY app/ app/
COPY alembic/ alembic/
COPY alembic.ini .

RUN pip install --no-cache-dir .

RUN mkdir -p /data

ENV FLAMEGUARD_DB_PATH=/tmp/flameguard.db

EXPOSE 8000

CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
