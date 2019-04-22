FROM python:3.7-alpine

WORKDIR /

# Default port
EXPOSE 9127

# Install dependencies
ADD requirements.txt /tasks_exporter/requirements.txt
RUN pip install -r /tasks_exporter/requirements.txt

# Default user
USER nobody

# Install main
ADD main.py /tasks_exporter/main.py

# Main script
ENTRYPOINT  [ "/tasks_exporter/main.py" ]

# Default commands
CMD [ "--listen-host", "0.0.0.0", \
      "--listen-port", "9127", \
      "--telemetry-path", "/metrics" ]
