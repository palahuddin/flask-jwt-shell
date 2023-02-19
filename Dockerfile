FROM python:3.6-slim-buster

WORKDIR /app
COPY . .

RUN pip install -r requirement.txt 

EXPOSE 5000
CMD python app.py