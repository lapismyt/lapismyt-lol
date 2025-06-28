FROM python:3.10-slim

ARG VENV=/opt/venv
WORKDIR /app

RUN adduser --disabled-login --gecos '' www-lapismyt-lol

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

RUN python -m venv ${VENV}
ENV PATH="${VENV}/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /app/uploads /app/instance && \
    chown -R www-lapismyt-lol:www-lapismyt-lol /app

COPY . .

USER www-lapismyt-lol

EXPOSE 5000

CMD ["waitress-serve", "--host=0.0.0.0", "--port=5000", "main:app"]
