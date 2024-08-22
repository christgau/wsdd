FROM python:alpine

RUN apk update && apk add --no-cache bash

RUN mkdir /code

COPY docker-entrypoint.sh /code
COPY src/wsdd.py /code

CMD [ "/code/docker-entrypoint.sh"]
