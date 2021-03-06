FROM python:3.8

RUN apt update  \
    && apt install -y ansible \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY ./linkurator_core ./linkurator_core
COPY ./scripts ./scripts
COPY ./tests ./tests
COPY ./requirements.txt ./requirements.txt
COPY ./.pylintrc ./.pylintrc
COPY ./mypy.ini ./mypy.ini
COPY ./Makefile ./Makefile
COPY ./config ./config

RUN make setup

EXPOSE 9000

CMD ["make", "run"]
