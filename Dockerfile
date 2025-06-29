FROM openpolicyagent/opa:latest

COPY policies/ /policies/
COPY inputs/ /inputs/

ENTRYPOINT ["opa"]
