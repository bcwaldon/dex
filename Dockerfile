FROM quay.io/brianredbeard/corebox

ADD bin/authd-worker /opt/authd/bin/authd-worker
ADD bin/authd-overlord /opt/authd/bin/authd-overlord
ADD bin/authctl /opt/authd/bin/authctl

ENV AUTHD_WORKER_HTML_ASSETS /opt/authd/html/
ADD static/html/* $AUTHD_WORKER_HTML_ASSETS

ENV AUTHD_WORKER_EMAIL_ASSETS /opt/authd/email/
ADD static/email/* $AUTHD_WORKER_EMAIL_ASSETS
ADD static/fixtures/emailer.json.sample $AUTHD_WORKER_EMAIL_ASSETS/emailer.json
