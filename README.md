authd
=====

[![Build Status](https://semaphoreci.com/api/v1/projects/52d56c45-8487-42ac-b124-056df1630122/411983/badge.svg)](https://semaphoreci.com/coreos-inc/auth)
[![Docker Repository on Quay.io](https://quay.io/repository/coreos/authd/status?token=64f952fa-9aa9-4f8e-ab8d-93bfbe770d25 "Docker Repository on Quay.io")](https://quay.io/repository/coreos/authd)


authd is a federated identity management service.
It provides OpenID Connect (OIDC) to users, while it proxies to multiple remote identity providers (IdP) to drive actual authentication.

## Architecture

authd consists of multiple components:

- **authd-worker** is the primary server component of authd
	- host a user-facing API that drives the OIDC protocol
	- proxy to remote identity providers via "connectors"
- **authd-overlord** is an auxiliary process responsible for two things:
	- rotation of keys used by the workers to sign identity tokens
	- garbage collection of stale data in the database
- **authctl** is CLI tool used to manage an authd deployment
	- configure identity provider connectors
	- administer OIDC client identities

A typical authd deployment consists of N authd-workers behind a load balanacer, and one authd-overlord.
The authd-workers directly handle user requests, so the loss of all workers can result in service downtime.
The single authd-overlord runs its tasks periodically, so it does not need to maintain 100% uptime.

## Connectors

Remote IdPs could implement any auth-N protocol.
*connectors* contain protocol-specific logic and are used to communicate with remote IdPs.
Possible examples of connectors could be: OIDC, LDAP, Local Memory, Basic Auth, etc.
authd ships with an OIDC connector, and a basic "local" connector for in-memory testing purposes.
Future connectors can be developed and added as future interoperability requirements emerge.

## Relevant Specifications

These specs are referenced and implemented to some degree in the `jose` package of this project.

- [JWK](https://tools.ietf.org/html/draft-ietf-jose-json-web-key-36)
- [JWT](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-30)
- [JWS](https://tools.ietf.org/html/draft-jones-json-web-signature-04)

OpenID Connect (OIDC) is broken up into several specifications. The following (amongst others) are relevant:

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)

## Example OIDC Discovery Endpoints

- https://accounts.google.com/.well-known/openid-configuration
- https://login.salesforce.com/.well-known/openid-configuration

# Building

## With Host Go Environment

`./build`

## With Docker

`./go-docker ./build`

## Docker Build and Push

Binaries must be compiled first.
Builds a docker image and pushes it to the quay repo.
The image is tagged with the git sha and 'latest'.

```
export QUAY_USER=xxx
export QUAY_PASSWORD=yyy
./build-docker-push
```

## Rebuild API from JSON schema

Go API bindings are generated from a JSON Discovery file.
To regenerate run:

```
./schema/generator
```

For updating generator dependencies see docs in: `schema/generator_import.go`.

## Runing Tests

Run all tests: `./test`

Single package only: `PKG=<pkgname> ./test`

Functional tests: `./test-functional`

Run with docker:

```
./go-docker ./test
./go-docker ./test-functional
```

# Running

Run the main authd server:

After building, run `./bin/authd` and provider the required arguments.
Additionally start `./bin/authd-overlord` for key rotation and database garbage collection.

# Deploying

Generate systemd unit files by injecting secrets into the unit file templates located in: `./static/...`.

```
source <path-to-secure>/prod/authd.env.txt
./build-units
```

Resulting unit files are output to: `./deploy`

# Registering Clients

Like all OAuth2 servers clients must be registered with a callback url.
New clients can be registered with the authctl CLI tool:
```
authctl new-client http://example.com/auth/callback
```

# Coming Soon

- Multiple backing Identity Providers
- Identity Management
- Authorization
