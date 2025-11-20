FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# system deps (minimal)
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# copy requirements first for better caching
COPY requirements.txt /app/

# install python deps (include gunicorn and eventlet for Socket.IO)
RUN pip install --upgrade pip \
    && pip install -r requirements.txt gunicorn eventlet

# copy project
COPY . /app

# ensure avatars folder exists
RUN mkdir -p /app/static/images/avatars

EXPOSE 5000

# Use gunicorn with eventlet worker for Flask-SocketIO
CMD ["gunicorn", "-k", "eventlet", "-w", "1", "app:app", "--bind", "0.0.0.0:5000"]
