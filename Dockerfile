FROM quay.io/brianredbeard/corebox

ADD bin/authd-worker /opt/authd/bin/authd-worker
ADD bin/authd-overlord /opt/authd/bin/authd-overlord
ADD bin/authctl /opt/authd/bin/authctl

ENV AUTHD_WORKER_HTML_ASSETS /opt/authd/html/
ADD static/html/local-login.html $AUTHD_WORKER_HTML_ASSETS
ADD static/html/login.html $AUTHD_WORKER_HTML_ASSETS
ADD static/html/register.html $AUTHD_WORKER_HTML_ASSETS
ADD static/html/verify-email.html $AUTHD_WORKER_HTML_ASSETS

ENV AUTHD_WORKER_HTML_ASSETS /opt/authd/email/
ADD static/email/verify-email.html $AUTHD_WORKER_EMAIL_ASSETS
ADD static/email/verify-email.txt $AUTHD_WORKER_EMAIL_ASSETS