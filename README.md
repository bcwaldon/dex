Core-Auth
=========

Centralized authentication and authorization.

## Components

Core-Auth consisists of various components:

1. A web app for users to authenticate with.
2. A web app for users to manage auth-z policies.
3. An API to serve auth-z queries.
4. A common library to: validate auth-n tokens, extract userids from auth-n tokens, and fetch auth-z policies for users.

## Design Strategy

- Users authenticate and are provided a JWT
- API keys are the same format JWT
- Apps use a common library to access core-auth API to fetch auth-z policies etc
- Auth-z policy requests supply an etag, policies are cached with a ttl


## Basic Flow

1. user logs in via ouath
1. user is redirected to app with token
1. app uses common lib to extract identity from token
1. app uses common lib to fetch auth-z policies (if not cached, or ttl expired)
1. app responds with denial/full-results/filter-results based on auth-z policies

## Policy Structure (WIP)


