Usage
-----

But court: how to use the demo compose with local builds and how to develop.

Build both images (recommended):

```bash
# build images referenced in the compose file
docker compose -f docker/demo/compose.yml build
```

Run (build automatically):

```bash
docker compose -f docker/demo/compose.yml up -d --build
```

Notes for development
---------------------

- To include your custom Keycloak provider JARs in the Keycloak image, put them in
  `docker/demo/keycloak/kc_providers/` (one or more .jar). The Dockerfile copies that
  directory into `/opt/keycloak/providers` at build time.

- Alternatively, keep the original behaviour and mount a host directory at runtime by
  providing a compose override file (example below).

Example `docker/demo/override.dev.yml` snippet to mount local folders during development:

```yaml
services:
  keycloak:
    volumes:
      - ./mounts/kc_providers:/opt/keycloak/providers:ro
  cf-auth-sim:
    volumes:
      - ./mounts/cf-auth-sim:/mnt/docker:ro
      - ./mounts/cf-auth-sim/nginx/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro
```

Then start with the override to avoid rebuilding the images:

```bash
docker compose -f docker/demo/compose.yml -f docker/demo/override.dev.yml up -d
```

Why this setup
----------------

- `compose.yml` now provides both `image` and `build` sections; you can either use the
  prebuilt upstream images (default) or build local images that include your provider
  and sim assets.

- Keeping the volumes in the compose file allows an easy dev workflow using an override
  file that mounts local files instead of relying on image contents.
