FROM quay.io/brianredbeard/corebox

ADD bin/authd /opt/authd/bin/authd
ADD bin/authd-overlord /opt/authd/bin/authd-overlord
ADD bin/authctl /opt/authd/bin/authctl

ENV AUTHD_HTML_ASSETS /opt/authd/html/
ADD static/html/login.html $AUTHD_HTML_ASSETS
ADD static/html/local-login.html $AUTHD_HTML_ASSETS
