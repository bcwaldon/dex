FROM quay.io/brianredbeard/corebox

ADD bin/authd /opt/authd/bin/authd
ADD bin/authd-overlord /opt/authd/bin/authd-overlord
ADD static/html/login.html /opt/authd/html/login.html
ADD static/html/local-login.html /opt/authd/html/local-login.html

CMD ["/opt/authd/bin/authd"]
