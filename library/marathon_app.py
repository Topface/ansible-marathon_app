#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2015, Ludovic Claude <ludovic.claude@laposte.net>
#

# TODO: operation fetch, version

DOCUMENTATION = """
module: marathon_app
version_added: "2.2"
short_description: start and stop applications with Marathon
description:
  - Start and stop applications with Marathon.
author: "Ludovic Claude (@ludovicc)"

options:
  uri:
    required: true
    description:
      - Base URI for the Marathon instance

  state:
    choices: [ present, absent, restart, kill ]
    default: "present"
    description:
      - The operation to perform.

  username:
    required: false
    default: null
    description:
      - The username to log-in with.

  password:
    required: false
    default: null
    description:
      - The password to log-in with.

  id:
    required: true
    description:
      - Unique identifier for the app consisting of a series of names separated by slashes.

  cmd:
    aliases: [ command ]
    required: false
    default: null
    description:
      - The command that is executed.

  args:
    aliases: [ arguments ]
    required: false
    default: null
    description:
      - An array of strings that represents an alternative mode of specifying the command to run.

  cpus:
    required: false
    default: 1.0
    description:
      - The number of CPU shares this application needs per instance. This number does not have to be integer, but can be a fraction.

  memory:
    aliases: [ mem ]
    required: false
    default: 128.0
    description:
      - The amount of memory in MB that is needed for the application per instance.

  disk:
    required: false
    default: 0.0
    description:
      - How much disk space in MB is needed for this application. This number does not have to be an integer, but can be a fraction.

  ports:
    required: false
    default: '[]'
    description:
      - An array of required port resources on the host. Required if C(require_ports=true).

  require_ports:
    aliases: [ requirePorts ]
    required: false
    default: false
    description:
      - If true, the ports you have specified are used as host ports.

  port_definitions:
    aliases: [ portDefinitions ]
    required: false
    default: '[]'
    description:
      - An array of required port resources on the agent host. The number of items in the array determines how many dynamic ports are allocated for every task. For every port definition with port number zero, a globally unique (cluster-wide) service port is assigned and provided as part of the app definition to be used in load balancing definitions.

  ip_address:
    aliases: [ ipAddress ]
    required: false
    default: null
    description:
      - If provided, then Marathon will request a per-task IP from Mesos. A separate ports/portMappings configuration is then disallowed.

  instances:
    required: false
    default: 1
    description:
      - The number of instances of this application to start.

  executor:
    required: false
    default: ""
    description:
      - The executor to use to launch this application.

  user:
    required: false
    default: null
    description:
      - The user to use to launch this application.

  container:
    required: false
    default: null
    description:
      - Additional data passed to the containerizer on application launch. This is a free-form data structure that can contain arbitrary data.

  docker_image:
    required: false
    default: null
    description:
      - Name of the Docker image. Ignored if container is defined.

  docker_force_pull_image:
    aliases: [ docker_forcePullImage ]
    required: false
    default: false
    description:
      - Force Docker to pull the image before launching each task. Ignored if container is defined.

  docker_privileged:
    required: false
    default: false
    description:
      - Allows users to run containers in privileged mode. Ignored if container is defined.

  docker_network:
    required: false
    default: 'NONE'
    description:
      - The networking mode, this container should operate in. One of BRIDGED|HOST|NONE. Ignored if container is defined.

  docker_port_mappings:
    aliases: [ docker_portMappings ]
    required: false
    default: null
    description:
      - Port mappings for the Docker container, an array of objects containing containerPort, hostPort, labels, name, protocol, servicePort properties. Ignored if container is defined.

  docker_parameters:
    required: false
    default: null
    description:
      - Arbitrary parameters for the Docker container. Ignored if container is defined.

  container_type:
    required: false
    default: DOCKER if docker_image is defined otherwise MESOS
    description:
      - Supported container types at the moment are DOCKER and MESOS. Ignored if container is defined.

  container_volumes:
    required: false
    default: null
    description:
      - Array of volumes for the container defining for each volume the properties containerPath, hostPath, mode, persistent (object with size property), external (object with size, name, provider and options properties). Ignored if container is defined.

  residency:
    required: false
    default: null
    description:
      - When using local persistent volumes that pin tasks onto agents, these values define how Marathon handles terminal states of these tasks.

  env:
    required: false
    default: '[]'
    description:
      - Key value pairs that get added to the environment variables of the process to start.

  constraints:
    required: false
    default: '[]'
    description:
      - Valid constraint operators are one of ["UNIQUE", "CLUSTER", "GROUP_BY", "LIKE", "UNLIKE"].

  accepted_resource_roles:
    aliases: [ acceptedResourceRoles ]
    required: false
    default: null
    description:
      - A list of resource roles.

  labels:
    required: false
    default: null
    description:
      - Attaching metadata to apps can be useful to expose additional information to other services, so we added the ability to place labels on apps.

  uris:
    required: false
    default: '[]'
    description:
      - URIs defined here are resolved, before the application gets started. If the application has external dependencies, they should be defined here.

  store_urls:
    aliases: [ storeUrls ]
    required: false
    default: '[]'
    description:
      - A sequence of URIs, that get fetched on each instance, that gets started. The artifact could be fetched directly from the source, or put into the artifact store. One simple way to do this is automatic artifact storing.

  dependencies:
    required: false
    default: '[]'
    description:
      - A list of services upon which this application depends.

  fetch:
    required: false
    default: '[]'
    description:
      - Provided URIs are passed to Mesos fetcher module and resolved in runtime. URIs are defined as objects with properties uri, executable, extract, cache.

  health_checks:
    aliases: [ healthChecks ]
    required: false
    default: '[]'
    description:
      - An array of checks to be performed on running tasks to determine if they are operating as expected.

  readiness_checks:
    aliases: [ readinessChecks ]
    required: false
    default: '[]'
    description:
      - An array of checks to be performed on running tasks to determine if they are ready to serve requests..

  backoff_seconds:
    aliases: [ backoffSeconds ]
    required: false
    default: 1
    description:
      - Configures exponential backoff behavior when launching potentially sick apps. The backoff period is multiplied by the factor for each consecutive failure until it reaches maxLaunchDelaySeconds.

  backoff_factor:
    aliases: [ backoffFactor ]
    required: false
    default: 1.15
    description:
      - Configures exponential backoff behavior when launching potentially sick apps. The backoff period is multiplied by the factor for each consecutive failure until it reaches maxLaunchDelaySeconds.

  max_launch_delay_seconds:
    aliases: [ maxLaunchDelaySeconds ]
    required: false
    default: 3600
    description:
      - Configures exponential backoff behavior when launching potentially sick apps. The backoff period is multiplied by the factor for each consecutive failure until it reaches maxLaunchDelaySeconds.

  upgrade_strategy_minimum_health_capacity:
    aliases: [ upgradeStrategy_minimumHealthCapacity ]
    required: false
    default: 1.0
    description:
      - A number between 0 and 1 that is multiplied with the instance count. This is the minimum number of healthy nodes that do not sacrifice overall application purpose.

  upgrade_strategy_maximum_over_capacity:
    aliases: [ upgradeStrategy_maximumOverCapacity ]
    required: false
    default: 0.0
    description:
      - A number between 0 and 1 which is multiplied with the instance count. This is the maximum number of additional instances launched at any point of time during the upgrade process.

  version:
    required: false
    default: null
    description:
      - The version of this definition, date-time format.

  versionInfo:
    required: false
    default: null
    description:
      - Detailed version information.

  force:
    required: false
    default: false
    description:
      - If the app is affected by a running deployment, then the update operation will fail. The current deployment can be overridden by setting the I(force) query parameter.

  wait_timeout:
    aliases: [ waitTimeout ]
    required: false
    default: 0
    description:
      - If set, wait for the application to become available until timeout seconds.

  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only be
        set to C(no) when no other option exists.  Prior to 1.9.3 the code
        defaulted to C(no).
    required: false
    default: 'yes'
    choices: ['yes', 'no']

author: "Ludovic Claude (@ludovicc)"
"""

EXAMPLES = """
# Launch Postgres in a Docker container using Marathon, wait for the deployment to complete
- name: Launch Postgres using Marathon
  marathon_app:
    uri: "{{ marathon_url }}"
    id: "/postgres"
    state: "present"
    docker_image: "postgres:{{ postgres_version }}"
    docker_force_full_image: true
    docker_network: BRIDGE
    docker_port_mappings:
      - hostPort: 31432
        containerPort: 5432
    container_volumes:
      - containerPath: "/var/lib/postgresql/data"
        hostPath: "{{ postgres_data_dir }}"
        mode: RW
    env:
      POSTGRES_USER: "{{ postgres_user }}"
      POSTGRES_PASSWORD: "{{ postgres_password }}"
    instances: 1
    cpus: 0.2
    mem: 128.0
    ports: []
    require_ports: false
    constraints: []
    dependencies: []
    executor: ""
    wait_timeout: 600
  async: 600
  poll: 1

# Remove an application from Marathon
- name: Remove an old app from Marathon
  marathon_app:
    uri: "{{ marathon_url }}"
    id: "/oldapp"
    state: "absent"
"""

RETURN = """
uri:
    description: URI of the Marathon application
    returned: success
    type: string
    sample: /my-app
state:
    description: state of the target, after execution
    returned: success
    type: string
    sample: "present"
meta:
    description: additional information returned by Marathon, depends on the operation performed
    returned: success
    type: object
"""

import base64

MARATHON_APP_PARAMETERS = ['cmd', 'args', 'cpus', 'mem', 'disk', 'ports', 'requirePorts', 'portDefinitions', 'ipAddress', 'instances', 'executor', 'user', 'container', 'residency', 'env', 'constraints', 'acceptedResourceRoles', 'labels', 'uris', 'storeUrls', 'dependencies', 'fetch', 'healthChecks', 'readinessChecks', 'backoffSeconds', 'backoffFactor', 'maxLaunchDelaySeconds', 'upgradeStrategy', 'version', 'versionInfo']

def fetch_url2(module, url, data=None, headers=None, method=None,
              use_proxy=True, force=False, last_mod_time=None, timeout=10):
    '''
    Variation of fetch_url returning more information in case of error
    '''

    if not HAS_URLLIB2:
        module.fail_json(msg='urllib2 is not installed')
    elif not HAS_URLPARSE:
        module.fail_json(msg='urlparse is not installed')

    # Get validate_certs from the module params
    validate_certs = module.params.get('validate_certs', True)

    username = module.params.get('url_username', '')
    password = module.params.get('url_password', '')
    http_agent = module.params.get('http_agent', None)
    force_basic_auth = module.params.get('force_basic_auth', '')

    follow_redirects = module.params.get('follow_redirects', 'urllib2')

    r = None
    info = dict(url=url)
    try:
        r = open_url(url, data=data, headers=headers, method=method,
                     use_proxy=use_proxy, force=force, last_mod_time=last_mod_time, timeout=timeout,
                     validate_certs=validate_certs, url_username=username,
                     url_password=password, http_agent=http_agent, force_basic_auth=force_basic_auth,
                     follow_redirects=follow_redirects)
        info.update(r.info())
        info['url'] = r.geturl()  # The URL goes in too, because of redirects.
        info.update(dict(msg="OK (%s bytes)" % r.headers.get('Content-Length', 'unknown'), status=200))
    except NoSSLError, e:
        distribution = get_distribution()
        if distribution is not None and distribution.lower() == 'redhat':
            module.fail_json(msg='%s. You can also install python-ssl from EPEL' % str(e))
        else:
            module.fail_json(msg='%s' % str(e))
    except (ConnectionError, ValueError), e:
        module.fail_json(msg=str(e))
    except urllib2.HTTPError, e:
        body = {}
        if e.code in (400, 401, 403, 409, 422):
            body = e.read()
        info.update(dict(msg=str(e), body=body, status=e.code, **e.info()))
    except urllib2.URLError, e:
        code = int(getattr(e, 'code', -1))
        info.update(dict(msg="Request failed: %s" % str(e), body=None, status=code))
    except socket.error, e:
        info.update(dict(msg="Connection failure: %s" % str(e), body=None, status=-1))
    except Exception, e:
        info.update(dict(msg="An unknown error occurred: %s" % str(e), body=None, status=-1))

    return r, info

def request(url, user=None, passwd=None, data=None, method=None):
    if data:
        data = json.dumps(data)

    if user is not None:
        auth = base64.encodestring('%s:%s' % (user, passwd)).replace('\n', '')
        response, info = fetch_url2(module, url, data=data, method=method,
                                   headers={'Content-Type':'application/json',
                                            'Authorization':"Basic %s" % auth})
    else:
        response, info = fetch_url2(module, url, data=data, method=method,
                                   headers={'Content-Type':'application/json'})

    if info['status'] not in (200, 201, 204):
        msg = info['msg']
        body = info['body']
        if body:
            body = json.loads(body)
        else:
            body = {}

        module.fail_json(msg=msg,response=body)

    body = response.read()

    if body:
        return json.loads(body)
    else:
        return {}

def tryRequest(url, user=None, passwd=None, data=None, method=None):
    if user is not None:
        auth = base64.encodestring('%s:%s' % (user, passwd)).replace('\n', '')
        response, info = fetch_url(module, url, data=data, method=method,
                                   headers={'Content-Type':'application/json',
                                            'Authorization':"Basic %s" % auth})
    else:
        response, info = fetch_url(module, url, data=data, method=method,
                                   headers={'Content-Type':'application/json'})

    body = {}

    if info['status'] in (200, 201, 204):
        raw_body = response.read()
        if raw_body:
            body = json.loads(raw_body)

    return (body, info)

def post(url, user, passwd, data):
    return request(url, user, passwd, data=data, method='POST')

def put(url, user, passwd, data):
    return request(url, user, passwd, data=data, method='PUT')

def get(url, user, passwd):
    return request(url, user, passwd)

def delete(url, user, passwd, params):
    ret, info = tryRequest(url, user, passwd, data=None, method='DELETE')

    if params['waitTimeout'] and info['status'] in (200, 204) and 'deploymentId' in ret:
        waitForDeployment(url, user, passwd, params, ret['deploymentId'])

    return {'meta': ret, 'changed': 'deploymentId' in ret}

def create(restbase, user, passwd, params):
    data = {'id': params['id']}

    # Merge in any additional or overridden fields
    for arg in MARATHON_APP_PARAMETERS:
        if params[arg]:
            data.update({arg: params[arg]})

    url = restbase + '/apps'

    ret = post(url, user, passwd, data)

    if params['waitTimeout']:
        waitForDeployment(restbase, user, passwd, params, ret['deployments'][0]['id'])

    return {'meta': ret, 'changed': True}

def edit(restbase, user, passwd, params):
    data = {'id': params['id']}

    # Merge in any additional or overridden fields
    for arg in MARATHON_APP_PARAMETERS:
        if params[arg]:
            data.update({arg: params[arg]})

    url = restbase + '/apps/' + params['id'] + '?force=' + str(params['force']).lower()

    ret = put(url, user, passwd, data)

    if params['waitTimeout']:
        waitForDeployment(restbase, user, passwd, params, ret['deploymentId'])

    return {'meta': ret, 'changed': 'deploymentId' in ret}

def waitForDeployment(restbase, user, passwd, params, deploymentId):
    timeout = time.time() + params['waitTimeout']

    while True:
        url = restbase + '/deployments'
        deployments, info = tryRequest(url, user, passwd)

        if info['status'] == 404:
          return

        if info['status'] in (200, 201, 204):
            deploymentIds = map(lambda x: x['id'], deployments)
            if deploymentId not in deploymentIds:
                return

        time.sleep(1)

        if time.time() > timeout:
            module.fail_json(msg='Timeout waiting for deployment.')

    return

def restart(restbase, user, passwd, params):
    data = {
        'force': params['force']
    }

    url = restbase + '/apps/' + params['id'] + '/restart'

    ret = post(url, user, passwd, data)

    if params['waitTimeout']:
        waitForDeployment(restbase, user, passwd, params, ret['deployments'][0]['id'])

    return {'meta': ret, 'changed': True}

def fetch(restbase, user, passwd, params):
    url = restbase + '/apps/' + params['id']
    ret = get(url, user, passwd)
    return ret

def versions(restbase, user, passwd, params):
    url = restbase + '/apps/' + params['id'] + '/versions'
    ret = get(url, user, passwd)
    return ret

def destroy(restbase, user, passwd, params):
    url = restbase + '/apps/' + params['id']
    ret = delete(url, user, passwd, params)
    return ret

def absent(restbase, user, passwd, params):
    return destroy(restbase, user, passwd, params)

def present(restbase, user, passwd, params):
    app, info = tryRequest(restbase + '/apps/' + params['id'], user, passwd)

    if info['status'] in (200, 204):
        # Destroy apps which seem stuck into deployment
        if len(app['app']['deployments']) > 0:
            destroy(restbase, user, passwd, params)
            return create(restbase, user, passwd, params)
        else:
            return edit(restbase, user, passwd, params)
    else:
        return create(restbase, user, passwd, params)

def kill(restbase, user, passwd, params):
    url = restbase + '/apps/' + params['id'] + '/tasks'
    ret = delete(url, user, passwd, params)

    if params['waitTimeout'] and 'deployments' in ret and len(ret['deployments']) > 0:
        waitForDeployment(restbase, user, passwd, params, ret['deployments'][0]['id'])

    return {'meta': ret, 'changed': 'deployments' in ret and len(ret['deployments']) > 0}

# Some parameters are required depending on the operation:
OP_REQUIRED = dict(absent=['id'],
                   present=['id'],
                   restart=['id'],
                   kill=['id'])

def main():

    global module
    module = AnsibleModule(
        argument_spec=dict(
            uri=dict(required=True),
            state=dict(default='present', choices=['absent', 'present', 'restart', 'kill']),
            username=dict(required=False,default=None),
            password=dict(required=False,default=None),
            id=dict(type='str',required=True),
            cmd=dict(aliases=['command'], type='str'),
            args=dict(aliases=['arguments'], type='list'),
            cpus=dict(type='float', default=1.0),
            mem=dict(default=128.0, aliases=['memory'],type='float'),
            disk=dict(default=0.0, type='float'),
            ports=dict(default=[], type='list'),
            requirePorts=dict(aliases=['require_ports'], default=False, type='bool'),
            portDefinitions=dict(aliases=['port_definitions'], default=[], type='list'),
            ipAddress=dict(aliases=['ip_address'],type='dict'),
            storeUrls=dict(aliases=['store_urls'], default=[], type='list'),
            instances=dict(default=1, type='int'),
            executor=dict(default="", type='str'),
            user=dict(type='str'),
            version=dict(type='str'),
            versionInfo=dict(aliases=['version_info'],type='dict'),
            container=dict(type='dict'),
            docker_image=dict(),
            docker_forcePullImage=dict(aliases=['docker_force_pull_image'], default=False, type='bool'),
            docker_privileged=dict(default=False, type='bool'),
            docker_network=dict(default='NONE', type='str'),
            docker_parameters=dict(default=[], type='list'),
            docker_portMappings=dict(aliases=['docker_port_mappings'], default=[], type='list'),
            container_type=dict(default='MESOS', type='str'),
            container_volumes=dict(default=[], type='list'),
            residency=dict(default={}, type='dict'),
            env=dict(default={}, type='dict'),
            constraints=dict(default=[], type='list'),
            acceptedResourceRoles=dict(aliases=['accepted_resource_roles'], default=[], type='list'),
            labels=dict(type='list'),
            uris=dict(default=[], type='list'),
            dependencies=dict(default=[], type='list'),
            fetch=dict(default=[], type='list'),
            healthChecks=dict(aliases=['health_checks'], default=[], type='list'),
            readinessChecks=dict(aliases=['readyness_checks'], default=[], type='list'),
            backoffSeconds=dict(aliases=['backoff_seconds'], type='float', default=1.0),
            backoffFactor=dict(aliases=['backoff_factor'], type='float', default=1.15),
            maxLaunchDelaySeconds=dict(aliases=['max_launch_delay_seconds'], type='float', default=3600.0),
            upgradeStrategy=dict(aliases=['upgrade_strategy'], default={}, type='dict'),
            upgradeStrategy_minimumHealthCapacity=dict(aliases=['upgrade_strategy_minimum_health_capacity'], default=0.0, type='float'),
            upgradeStrategy_maximumOverCapacity=dict(aliases=['upgrade_strategy_maximum_over_capacity'], default=0.0, type='float'),
            force=dict(default=False, type='bool'),
            waitTimeout=dict(aliases=['wait_timeout'], type='int'),
            validate_certs=dict(required=False, default=True, type='bool')

        ),
        supports_check_mode=False
    )

    state = module.params['state']

    # Check we have the necessary per-operation parameters
    missing = []
    for parm in OP_REQUIRED[state]:
        if not module.params[parm]:
            missing.append(parm)
    if missing:
        module.fail_json(msg="Operation %s require the following missing parameters: %s" % (state, ",".join(missing)))

    # Handle rest of parameters
    uri = module.params['uri']
    user = module.params['username']
    passwd = module.params['password']

    # Ensure that we use int values for ports
    if module.params['ports']:
        ports = module.params['ports']
        ports = [int(port) for port in ports]
        module.params['ports'] = ports

    # Ensure that we use int values for ports in port definitions
    if module.params['portDefinitions']:
        portDefinitions = module.params['portDefinitions']
        for portDefinition in portDefinitions:
            if 'port' in portDefinition:
              portDefinition['port'] = int(portDefinition['port'])
        module.params['portDefinitions'] = portDefinitions

    # Ensure that we use int values for port mappings
    if module.params['docker_portMappings']:
        mappings = module.params['docker_portMappings']
        for mapping in mappings:
            for param in ['containerPort', 'hostPort', 'servicePort']:
                if param in mapping:
                    mapping[param] = int(mapping[param])
        module.params['docker_portMappings'] = mappings

    # Ensure that we use int values for some healthChecks parameters
    if module.params['healthChecks']:
        healthChecks = module.params['healthChecks']
        for checks in healthChecks:
            for param in ['port', 'gracePeriodSeconds', 'intervalSeconds', 'timeoutSeconds', 'maxConsecutiveFailures']:
                if param in checks:
                    checks[param] = int(checks[param])
        module.params['healthChecks'] = healthChecks

    # Ensure that we use string values for env parameters
    if module.params['env']:
        env = module.params['env']
        for key, value in env.iteritems():
          env[key] = str(env[key])
        module.params['env'] = env

    if module.params['docker_image'] and not module.params['container']:
        module.params['container'] = { 'type': 'DOCKER', 'docker': { 'image': module.params['docker_image'], 'forcePullImage': bool(module.params['docker_forcePullImage']), 'privileged': bool(module.params['docker_privileged']), 'network': module.params['docker_network'], 'parameters': module.params['docker_parameters'], 'portMappings': module.params['docker_portMappings']}, 'volumes': module.params['container_volumes']}
    else:
        if module.params['container_volumes'] and not module.params['container']:
            module.params['container'] = { 'type': module.params['container_type'], 'volumes': module.params['container_volumes']}

    if module.params['upgradeStrategy_minimumHealthCapacity']:
        module.params['upgradeStrategy'].update({'minimumHealthCapacity': module.params['upgradeStrategy_minimumHealthCapacity']})

    if module.params['upgradeStrategy_maximumOverCapacity']:
        module.params['upgradeStrategy'].update({'maximumOverCapacity': module.params['upgradeStrategy_maximumOverCapacity']})

    if not uri.endswith('/'):
        uri = uri + '/'
    restbase = uri + 'v2'

    # Dispatch
    try:

        # Lookup the corresponding method for this operation. This is
        # safe as the AnsibleModule should remove any unknown operations.
        thismod = sys.modules[__name__]
        method = getattr(thismod, state)

        ret = method(restbase, user, passwd, module.params)

    except Exception, e:
        return module.fail_json(msg=e.message)


    module.exit_json(changed=ret['changed'], uri=uri, state=state, meta=ret['meta'])


from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
if __name__ == '__main__':
    main()
