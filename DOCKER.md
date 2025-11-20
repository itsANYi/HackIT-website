Docker usage for hacker-it-club-website

Build image locally:

```bash
# from project root
docker build -t hacker-it-club:latest .
```

Run container:

```bash
docker run -p 5000:5000 --name hacker-it-club -v $(pwd)/static/images/avatars:/app/static/images/avatars -d hacker-it-club:latest
```

Or with docker-compose (recommended for development):

```bash
docker compose up --build
```

Notes:
- The container starts the app with Gunicorn + Eventlet to support Flask-SocketIO.
- If you push this repo to GitHub and want to build on CI, make sure to include `requirements.txt` and any secret/config management outside the image.
- The container creates `/app/static/images/avatars` for uploaded avatars; the compose file mounts it to persist uploads locally.
