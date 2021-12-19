FROM node:16

COPY ./entrypoint.sh /entrypoint.sh
RUN chmod u+x /entrypoint.sh

WORKDIR /code/trellis-signer

CMD '/entrypoint.sh'

