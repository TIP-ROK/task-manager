FROM python:3.10

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONNUNBUFFERED 1

WORKDIR /usr/src/app

RUN pip install --upgrade pip

COPY . .

RUN pip install -r requirements.txt
