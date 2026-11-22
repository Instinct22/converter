FROM victoriametrics/vmagent:v1.156.0 AS telemetry
FROM python:3.12-slim
COPY --from=telemetry /vmagent-prod /usr/local/bin/vmagent
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY tests ./tests
ENV HOST=0.0.0.0 PORT=8080
EXPOSE 8080
VOLUME /app/data
CMD ["python", "-m", "app"]
