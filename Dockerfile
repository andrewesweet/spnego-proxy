FROM gcr.io/distroless/static-debian12:nonroot
COPY spnego-proxy /usr/local/bin/spnego-proxy
ENTRYPOINT ["spnego-proxy"]
