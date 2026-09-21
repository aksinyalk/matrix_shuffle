FROM frikky/shuffle:app_sdk as base

FROM base as builder

RUN apk --no-cache add --update alpine-sdk libffi libffi-dev musl-dev openssl-dev \
    git zlib-dev python3-dev rust cargo

RUN mkdir /install
WORKDIR /install
COPY requirements.txt /requirements.txt
RUN python3 -m pip install --no-cache-dir --upgrade --prefix="/install" -r /requirements.txt

FROM base
COPY --from=builder /install /usr/local
COPY src /app

RUN apk --no-cache add jq git curl libgcc

RUN mkdir -p /app/nio_store
VOLUME ["/app/nio_store"]

WORKDIR /app
CMD ["python", "app.py", "--log-level", "DEBUG"]
