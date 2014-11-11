package oidc

type LoginFunc func(ident Identity, clientID string) (code string, err error)
