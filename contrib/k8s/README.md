# authd

## Getting Started

**Warning**: Hacks Ahead.

You must be running cluster wide DNS for this to work. See https://github.com/coreos-inc/jelly/pull/186

Install your dockercfg. There is no nice way to do this:

```
ssh worker
cat > /proc/$(pgrep kubelet)/cwd/.dockercfg
```

Start postgres

```
kubectl create -f postgres-rc.yaml
kubectl create -f postgres-service.yaml
```

Run authd and setup services

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
