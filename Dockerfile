FROM python:3.6-alpine

WORKDIR /tasks_exporter

ADD requirements.txt .

RUN pip install -r ./requirements.txt

ADD main.py .

USER nobody

WORKDIR /

# Expose default port
EXPOSE 9127

# Main script
ENTRYPOINT  [ "/tasks_exporter/main.py" ]

# Default commands
CMD [ "--listen-host '0.0.0.0'", \
      "--listen-port 9127", \
      "--telemetry-path '/metrics'" ]
