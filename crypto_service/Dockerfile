FROM python:3.10-slim

WORKDIR /app

COPY ./requirements.txt /app
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

EXPOSE 7070

CMD ["python3","-u", "crypto_service.py"]