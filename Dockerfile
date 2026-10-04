# ProofLog: one container with the AI backend and the dashboard.
# Stage 1 builds the dashboard; stage 2 runs the FastAPI backend, which serves it.

FROM node:22-slim AS dashboard
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY engine/ engine/
COPY examples/ examples/
COPY --from=dashboard /app/frontend/dist frontend/dist
# Hosts like Render set PORT; locally it defaults to 8000.
ENV PORT=8000
EXPOSE 8000
CMD ["sh", "-c", "uvicorn engine.api:app --host 0.0.0.0 --port ${PORT}"]
