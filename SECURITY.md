# Security policy

## Reporting a vulnerability

Report vulnerabilities privately, not in a public issue. Use
[Report a vulnerability](https://github.com/alexvikman/nginx-proxy/security/advisories/new)
on the repository's Security tab.

A report is easiest to act on when it has:

- the image tag or digest;
- what is needed to reproduce it: the environment and labels of the
  containers involved, the proxy's environment, and any mounted files;
- what an attacker gains.

## Supported versions

Fixes are released as a new image. Only the newest image is supported:
`latest`, or the most recent version tag.

## Scope

The trust boundaries are described under [Security](README.md#security) in
the README. A container is trusted to serve the hosts it announces, but
nothing more. These are vulnerabilities:

- a container's environment or labels change the nginx configuration beyond
  the routing of its own hosts: injected directives or variables, connections
  to destinations other than the container, or files read from or written to
  the proxy;
- a request gets past `NETWORK_ACCESS`, basic authentication or the TLS
  settings that the configuration asks for;
- the ACME client writes outside `/etc/nginx/certs` and the challenge
  directory, or requests a certificate for a host the container does not
  serve.

These are not:

- a container that announces a `VIRTUAL_HOST` another container already
  serves. Limit which containers the proxy considers with
  `DOCKER_CONTAINER_FILTERS`;
- anything that needs access to the Docker socket, the proxy's environment or
  the files mounted into it.

## Verifying an image

Images are signed in the release workflow. See
[Releases and updates](README.md#releases-and-updates) for the command that
verifies a signature.
