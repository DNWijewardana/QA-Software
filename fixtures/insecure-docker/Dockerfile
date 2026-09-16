# FIXTURE — intentionally insecure Dockerfile for the golden corpus (spec X.3). NOT for real use.

# SEEDED: unpinned base image (IAC-DOCKER-TAG-001)
FROM node:latest

# SEEDED: hardcoded secret baked into an image layer (IAC-DOCKER-SECRET-001)
ENV API_KEY=abcd1234secretvalue

# SEEDED: remote script piped into a shell during build (IAC-DOCKER-CURLBASH-001)
RUN curl http://example.com/install.sh | sh

# SEEDED: apt install without cache cleanup (IAC-DOCKER-APTCLEAN-001)
RUN apt-get update && apt-get install -y curl

# SEEDED: ADD fetching a remote URL (IAC-DOCKER-ADD-001)
ADD https://example.com/app.tar.gz /app/

WORKDIR /app
COPY . /app

# SEEDED: no USER -> runs as root (IAC-DOCKER-USER-001)
# SEEDED: no HEALTHCHECK (IAC-DOCKER-HEALTHCHECK-000)
CMD ["node", "server.js"]
