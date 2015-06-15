# This file will do everything necessary to bring up a working AuthD
# environment, connected to a Postgres DB and with a local and Google OIDC
# connector; When the script is completed, you will have three processes running
# in the background of your (bash) shell: an AuthD Overlord, an AuthD Worker,
# and the example app.
#
# It assumes you are in the root directory of the AuthD project and that you
# have psql installed and running.
#
# USAGE:
#
# AUTHD_GOOGLE_CLIENT_ID=<<your_client_id>> AUTHD_GOOGLE_CLIENT_SECRET=<<your_client_secret>> && source  contrib/standup-db.sh
#
# NOTE: As you can see from above, this file is meant to be *sourced* not executed directly.

# Build components.
./build

# Set DB var
AUTHD_DB=authd_dev
AUTHD_DB_URL=postgres://localhost/$AUTHD_DB?sslmode=disable
export AUTHD_WORKER_DB_URL=$AUTHD_DB_URL

# Delete/create DB
dropdb $AUTHD_DB; createdb $AUTHD_DB

# Create a client 
eval "$(./bin/authctl -db-url=$AUTHD_DB_URL new-client http://127.0.0.1:5555/callback)"

# Set up connectors
AUTHD_CONNECTORS_FILE=$(mktemp  /tmp/authd-conn.XXXXX)
AUTHD_GOOGLE_ISSUER_URL=https://accounts.google.com 
cat << EOF > $AUTHD_CONNECTORS_FILE
[
	{
		"type": "local",
		"id": "local"
	},
	{
		"type": "oidc",
		"id": "google",
		"issuerURL": "$AUTHD_GOOGLE_ISSUER_URL",
		"clientID": "$AUTHD_GOOGLE_CLIENT_ID",
		"clientSecret": "$AUTHD_GOOGLE_CLIENT_SECRET"
	}
]
EOF

./bin/authctl -db-url=$AUTHD_DB_URL set-connector-configs $AUTHD_CONNECTORS_FILE

# Start the overlord
export AUTHD_OVERLORD_DB_URL=$AUTHD_DB_URL
export AUTHD_OVERLORD_KEY_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export AUTHD_OVERLORD_KEY_PERIOD=1h
./bin/authd-overlord &

# Start the worker
export AUTHD_WORKER_DB_URL=$AUTHD_DB_URL
export AUTHD_WORKER_KEY_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export AUTHD_WORKER_LOG_DEBUG=1
./bin/authd-worker &

# Start the app
./bin/example-app --client-id=$AUTHD_APP_CLIENT_ID --client-secret=$AUTHD_APP_CLIENT_SECRET --discovery=http://127.0.0.1:5556 &

# Create Admin User - the password is a hash of the word "password"
curl -X POST --data '{"email":"admin@example.com","password":"$2a$04$J54iz31fhYfXIRVglUMmpufY6TKf/vvwc9pv8zWog7X/LFrFfkNQe" }' http://127.0.0.1:5557/api/v1/admin

