ARG BASE_IMAGE=python:alpine
FROM $BASE_IMAGE

RUN apk add --no-cache bash

RUN mkdir /code

COPY docker-entrypoint.sh /code
COPY src/wsdd.py /code

CMD [ "/code/docker-entrypoint.sh"]
