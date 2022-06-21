FROM python:3.8

RUN mkdir /app
WORKDIR /app
RUN pip install -U pip
RUN apt-get update && apt-get install -y knot && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install -r requirements.txt

COPY sidecar.py /app
