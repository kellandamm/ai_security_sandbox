FROM openpolicyagent/opa:latest-static
COPY policies/ /policies/
CMD ["run", "--server", "--v0-compatible", "--addr=0.0.0.0:8181", "--log-level=info", "/policies/"]
