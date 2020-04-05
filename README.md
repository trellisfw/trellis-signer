# trellis-signer
A microservice to add a signature to resourcs.  Uses [https://github.com/oada/oada-jobs] to manage
a job queue of which resources to sign.  POST a resource into it's job queue and it will sign it
if it is not already signed.  The signature type is `transcription` by default.

## Installation
```docker-compose
cd path/to/your/oada-srvc-docker
cd services-available
git clone git@github.com:trellisfw/trellis-signer.git
cd ../services-enabled
ln -s ../services-available/trellis-signer .
oada up -d trellis-signer
```

## Overriding defaults for Production
Using the common `z_tokens` method outlined for `oada-srvc-docker`, the following entries
for the `z_tokens` docker-compose file will work:
```docker-compose
  trellis-signer:
    volumes:
      - ./services-available/z_tokens/private_key.jwk:/private_key.jwk
    environment:
      - token=atokentouseinproduction
      - domain=your.trellis.domain
      - privateJWK=/private_key.jwk
```

Note that the `volumes` part places a production private key for signing into the container,
overriding the *completely-not-private-at-all* `private_key.jwk` that comes bundled by default.


