Running Examples
===

The quickest way to start experimenting with authd is to run a single authd-worker locally, with an in-process 
database, and then interacting with it using the example programs in this directory.


## Build Everything and Start authd-worker

This section is required for both the Example App and the Example CLI. 

1. Build everything:
   ```
   ./build
   ```
   
1. Copy `static/fixtures/connectors.json.sample`
    ```
    cp static/fixtures/connectors.json.sample static/fixtures/connectors.json
    ```
    
1. Run authd_worker in local mode.
    ```
    ./bin/authd-worker --no-db &
    ```


## Example App

1. Build and run example app webserver, pointing the discovery URL to local Authd, and 
supplying the client information from `./static/fixtures/clients.json` into the flags.
   ```
   ./bin/app --client-id=XXX --client-secret=secrete --discovery=http://127.0.0.1:5556 
   ```

1. Navigate browser to `http://localhost:5555` and click "login" link
1. Click "Login with Local"
1. Enter in sample credentials from `static/fixtures/connectors.json`:
   ```
   user: elroy77
   password: bones
   ```
1. Observe user information in example app.
  
## Example CLI
*TODO*
