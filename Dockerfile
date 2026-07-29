FROM python:3.13-alpine

LABEL org.opencontainers.image.title="Unraid Disk Access Monitor"
LABEL org.opencontainers.image.description="Correlates Unraid HDD spin-ups with fanotify filesystem events"
LABEL org.opencontainers.image.version="1.0"

WORKDIR /app

COPY monitor.py /app/monitor.py

RUN python -m py_compile /app/monitor.py

# The process must run as root: entering the host mount namespace, chrooting
# into it, and mount-wide fanotify marks all require it. There is no
# unprivileged user to drop to here - see docker-compose.yml and README.md for
# what that means for host filesystem access.
USER root

# Runtime default working directory - deliberately not /app. Once monitor.py
# does its setns()+chroot() dance, any later process exec'd into this
# container (docker exec, HEALTHCHECK) is rooted at the Unraid host's own
# filesystem, not this image's rootfs - /app only exists in the image, never
# on the host, so a freshly exec'd process starting with cwd=/app would fail
# before it even runs anything. "/" exists everywhere.
WORKDIR /

ENTRYPOINT ["python", "-u", "/app/monitor.py"]
