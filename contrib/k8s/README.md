# authd

## Getting Started

**Warning**: Hacks Ahead.

1. Install your dockercfg. There is no nice way to do this:

```
ssh worker
cat > /proc/$(pgrep kubelet)/cwd/.dockercfg
```

2. Start postgres and get the service ip

```
kubectl create -f postgres-rc.yaml
kubectl create -f postgres-service.yaml
kubectl describe service authd-postgres | grep '^IP:' | awk '{print $2}'
```

3. Edit authd-overlord-rc.yaml authd-worker-rc.yaml and put the IP into the DB URL

4. Run authd and setup services

```
for i in authd-overlord-rc.yaml authd-overlord-service.yaml authd-worker-rc.yaml authd-worker-service.yaml; do 
	kubectl create -f ${i}
done
```

curl http://$(kubectl describe service authd-worker | grep '^IP:' | awk '{print $2}'):5556

5. [Register your first client](https://github.com/coreos-inc/auth#registering-clients)

## Debugging

You can use a port forward from the target host to debug the database

IP=$(kubectl describe service authd-postgres | grep '^IP:' | awk '{print $2}')
ssh -F ssh-config -L 5432:${IP}:5432 w1
psql -h localhost -w -U postgres
