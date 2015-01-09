package schema
//
// This file is automatically generated by schema/generator
//
// **** DO NOT EDIT ****
//
const DiscoveryJSON = `{
  "kind": "discovery#restDescription",
  "discoveryVersion": "v1",
  "id": "authd:v1",
  "name": "schema",
  "version": "v1",
  "title": "Authd API",
  "description": "The Authd REST API",
  "documentationLink": "http://github.com/coreos-inc/auth",
  "protocol": "rest",
  "icons": {
    "x16": "",
    "x32": ""
  },
  "labels": [],
  "baseUrl": "$ENDPOINT/api/v1/",
  "basePath": "/api/v1/",
  "rootUrl": "$ENDPOINT/",
  "servicePath": "api/v1/",
  "batchPath": "batch",
  "parameters": {},
  "auth": {},
  "schemas": {
    "Error": {
      "id": "Error",
      "type": "object",
      "properties": {
        "error": {
          "type": "string"
        },
        "error_description": {
          "type": "string"
        }
      }
    },
    "Client": {
      "id": "Client",
      "type": "object",
      "properties": {
        "client_name": {
          "type": "string"
        },
        "client_id": {
          "type": "string"
        },
        "redirect_uris": {
          "required": true,
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      }
    },
    "ClientWithSecret": {
      "id": "Client",
      "type": "object",
      "properties": {
        "client_name": {
          "type": "string"
        },
        "client_id": {
          "type": "string"
        },
        "client_secret": {
          "type": "string"
        },
        "redirect_uris": {
          "required": true,
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      }
    },
    "ClientPage": {
      "id": "ClientPage",
      "type": "object",
      "properties": {
        "clients": {
          "type": "array",
          "items": {
            "$ref": "Client"
          }
        },
        "nextPageToken": {
          "type": "string"
        }
      }
    }
  },
  "resources": {
    "Clients": {
      "methods": {
        "List": {
          "id": "authd.Client.List",
          "description": "Retrieve a page of Client objects.",
          "httpMethod": "GET",
          "path": "clients",
          "parameters": {
            "nextPageToken": {
              "type": "string",
              "location": "query"
            }
          },
          "response": {
            "$ref": "ClientPage"
          }
        },
        "Create": {
          "id": "authd.Client.Create",
          "description": "Register a new Client.",
          "httpMethod": "POST",
          "path": "clients",
          "request": {
            "$ref": "Client"
          },
          "response": {
            "$ref": "ClientWithSecret"
          }
        }
      }
    }
  }
}
`