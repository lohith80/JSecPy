FROM python:3.12-slim

RUN useradd --create-home --uid 10001 scanner
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

USER scanner
WORKDIR /scan

# Mount your source at /scan and pass paths/flags as arguments:
#   docker run --rm -v "$PWD:/scan" jsecpy . --format sarif -o out.sarif
ENTRYPOINT ["jsecpy"]
CMD ["--help"]
