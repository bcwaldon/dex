package adminschema
//
// This file is automatically generated by schema/generator
//
// **** DO NOT EDIT ****
//
const DiscoveryJSON = `{
  "kind": "discovery#restDescription",
  "discoveryVersion": "v1",
  "id": "authd:v1",
  "name": "adminschema",
  "version": "v1",
  "title": "Authd Admin API",
  "description": "The Authd Admin API.",
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
      "Admin": {
          "id": "Admin",
          "type": "object",
          "properties": {
              "id": {
                  "type": "string"
              },
              "name": {
                  "type": "string"
              },
              "passwordHash": {
                  "type": "string"
              }
          }
      },
      "State": {
          "id": "State",
          "type": "object",
          "properties": {
              "AdminUserCreated": {
                  "type": "boolean"
              }
          }
      }
  },
  "resources": {
      "Admin": {
          "methods": {
              "Get": {
                  "id": "authd.admin.Admin.Get",
                  "description": "Retrieve information about an admin user.",
                  "httpMethod": "GET",
                  "path": "admin/{id}",
                  "parameters": {
                      "id": {
                          "type": "string",
                          "required": true,
                          "location": "path"
                      }
                  },
                  "parameterOrder": [
                      "id"
                  ],
                  "response": {
                      "$ref": "Admin"
                  }
                  
              },
              "Create": {
                  "id": "authd.admin.Admin.Create",
                  "description": "Create a new admin user.",
                  "httpMethod": "POST",
                  "path": "admin",
                  "request": {
                      "$ref": "Admin"
                  },
                  "response": {
                      "$ref": "Admin"
                  }
              }
          }
      },
      "State": {
          "methods": {
              "Get": {
                  "id": "authd.admin.State.Get",
                  "description": "Get the state of the AuthD DB",
                  "httpMethod": "GET",
                  "path": "state",
                  "response": {
                      "$ref": "State"
                  }
              }
          }
      }
  }
}
`