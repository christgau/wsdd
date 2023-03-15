FROM python:slim

RUN mkdir /code

COPY docker-entrypoint.sh /code
COPY src/wsdd.py /code

CMD [ "/code/docker-entrypoint.sh"]
