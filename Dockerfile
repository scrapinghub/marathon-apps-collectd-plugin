FROM python:3.6-alpine

WORKDIR /tasks_exporter

ADD requirements.txt .

RUN pip install -r ./requirements.txt

ADD main.py .

USER nobody

WORKDIR /

ENTRYPOINT  [ "/tasks_exporter/main.py" ]
