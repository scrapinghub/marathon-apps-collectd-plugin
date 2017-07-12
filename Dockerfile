FROM python:3.6-alpine

WORKDIR /tasks_exporter

ADD requirements.txt .

RUN pip install -r ./requirements.txt

ADD main.py .

USER nobody

WORKDIR /

# Allow configuration through environment variables
ENV EXPORTER_LISTEN_HOST=0.0.0.0 \
    EXPORTER_LISTEN_PORT=9127 \
    EXPORTER_TELEMETRY_PATH=/metrics

# Expose default port
EXPOSE 9127

# Main script
ENTRYPOINT  [ "/tasks_exporter/main.py" ]

# Default commands
CMD [ "--listen-host $EXPORTER_LISTEN_HOST", \
      "--listen-port $EXPORTER_LISTEN_PORT", \
      "--telemetry-path $EXPORTER_TELEMETRY_PATH" ]
