FROM python:3.7-alpine

WORKDIR /

# Default user
USER nobody

# Default port
EXPOSE 9127

# Install dependencies
ADD requirements.txt /tasks_exporter
RUN pip install -r /tasks_exporter/requirements.txt

# Install main
ADD main.py /tasks_exporter

# Main script
ENTRYPOINT  [ "/tasks_exporter/main.py" ]

# Default commands
CMD [ "--listen-host", "0.0.0.0", \
      "--listen-port", "9127", \
      "--telemetry-path", "/metrics" ]
