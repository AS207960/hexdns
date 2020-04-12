FROM python:3.8

RUN mkdir /app
RUN useradd app
WORKDIR /app
RUN pip install -U pip

COPY requirements.txt /app/
RUN pip install -r requirements.txt

USER app:app

COPY . /app
