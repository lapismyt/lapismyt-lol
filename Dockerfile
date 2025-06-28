FROM python:3.10-slim

ARG VENV=/opt/venv

WORKDIR /app

RUN adduser --disabled-login --gecos '' www-lapismyt-lol

RUN python -m venv ${VENV}

ENV PATH="${VENV}/bin:$PATH"

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

USER www-lapismyt-lol

EXPOSE 5000

CMD ["waitress-serve", "--host=0.0.0.0", "--port=5000", "main:app"]
