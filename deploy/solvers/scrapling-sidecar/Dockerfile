# The Scrapling image carries Scrapling and its browser stack; the sidecar
# only adds the HTTP contract on top. `uv run` is the image's own
# environment — its system python does not have Scrapling's dependencies.
FROM pyd4vinci/scrapling:latest

COPY server.py /app/brandbrain-scrapling-sidecar.py

ENV PORT=8000
EXPOSE 8000

ENTRYPOINT ["uv", "run", "python", "/app/brandbrain-scrapling-sidecar.py"]
