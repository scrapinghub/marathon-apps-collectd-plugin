FROM python:3.6-alpine

ADD requirements.txt /tasks_exporter/

RUN pip install -r /requirements.txt

EXPOSE 9327

USER        nobody

ENTRYPOINT  [ "python" ]

CMD [ "main.py" ]
