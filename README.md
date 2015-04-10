# topface.marathon_app

Deploy apps on [Marathon](https://mesosphere.github.io/marathon/) from ansible.

## Usage

This role deploys app on Marathon via `PUT /v2/apps/{appId}` API.

### Role configuration

* `marathon_url` url of Marathon, example: `http://marathon.dev:8080`
* `marathon_wait_for_deployment` whether to block until deployment is finished,
set to `true` by default
* `marathon_app` marathon application definition, see
[docs](https://mesosphere.github.io/marathon/docs/rest-api.html#post-/v2/apps)

### Example

The next playbook deploys [Chronos](https://airbnb.github.io/chronos/)
on marathon with single instance and waits for deployment to finish.

```yaml
- hosts: marathon-api-server
  gather_facts: no
  roles:
    - role: topface.marathon_app
      tags:
        - chronos
      marathon_url: http://marathon.dev:8080
      marathon_app:
        id: /chronos
        cmd: exec /usr/bin/chronos run_jar --cluster_name Dev --http_port $PORT --master zk://zk:2181/mesos --zk_hosts zk:2181 --mesos_framework_name chronos
        container:
          type: DOCKER
          docker:
            image: mesosphere/chronos:chronos-2.3.2-0.1.20150207000917.ubuntu1404-mesos-0.21.1-1.1.ubuntu1404
        instances: 1
        cpus: 0.5
        mem: 512
        ports:
          - 10101
        labels:
          marathoner_haproxy_enabled: "true"
        healthChecks:
          - protocol: HTTP
            path: /scheduler/jobs
            gracePeriodSeconds: 15
            maxConsecutiveFailures: 3
            intervalSeconds: 5
            timeoutSeconds: 5
```

See [topface.chronos_task](https://github.com/Topface/ansible-chronos_task)
to learn how to run tasks on Chronos launched this way.

## License

MIT
