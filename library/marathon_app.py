#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2015, Ludovic Claude <ludovic.claude@laposte.net>
#

# TODO: operation fetch, version

DOCUMENTATION = """
module: marathon_app
version_added: "1.9"
short_description: start and stop applications with Marathon
description:
  - Start and stop applications with Marathon.

options:
  uri:
    required: true
    description:
      - Base URI for the Marathon instance

  state:
    required: true
    choices: [ present, absent, restart, kill ]
    default: "present"
    description:
      - The operation to perform.

  username:
    required: false
    description:
      - The username to log-in with.

  password:
    required: false
    description:
      - The password to log-in with.

  id:
    required: true
    description:
      - Unique identifier for the app consisting of a series of names separated by slashes.

  command:
    aliases: [ cmd ]
    required: false
    description:
      - The command that is executed.

  arguments:
    aliases: [ args ]
    required: false
    description:
      - An array of strings that represents an alternative mode of specifying the command to run.

  cpus:
    required: false
    description:
     - The number of CPU`s this application needs per instance. This number does not have to be integer, but can be a fraction.

  memory:
    aliases: [ mem ]
    required: false
    description:
     - The amount of memory in MB that is needed for the application per instance.

  ports:
    required: false
    description:
     - An array of required port resources on the host.

  requirePorts:
    required: false
    description:
     - If true, the ports you have specified are used as host ports.

  instances:
    required: false
    description:
     - The number of instances of this application to start.

  executor:
    required: false
    description:
     - The executor to use to launch this application.

  container:
    required: false
    description:
     - Additional data passed to the containerizer on application launch. This is a free-form data structure that can contain arbitrary data.

  docker_image:
    required: false
    description:
     - Name of the Docker image. Ignored if container is defined.

  docker_forcePullImage:
    required: false
    description:
     - Force Docker to pull the image before launching each task. Ignored if container is defined.

  docker_privileged:
    required: false
    description:
     - Allows users to run containers in privileged mode. Ignored if container is defined.

  docker_network:
    required: false
    description:
     - Type of networking for the Docker container. Ignored if container is defined.

  docker_portMappings:
    required: false
    description:
     - Port mappings for the Docker container. Ignored if container is defined.

  docker_parameters:
    required: false
    description:
     - Arbitrary parameters for the Docker container. Ignored if container is defined.

  container_volumes:
    required: false
    description:
     - Array of volumes for the container. Ignored if container is defined.

  env:
    required: false
    description:
     - Key value pairs that get added to the environment variables of the process to start.

  constraints:
    required: false
    description:
     - Valid constraint operators are one of ["UNIQUE", "CLUSTER", "GROUP_BY"].

  acceptedResourceRoles:
    required: false
    description:
     - A list of resource roles.

  labels:
    required: false
    description:
     - Attaching metadata to apps can be useful to expose additional information to other services, so we added the ability to place labels on apps.

  uris:
    required: false
    description:
     - URIs defined here are resolved, before the application gets started. If the application has external dependencies, they should be defined here.

  dependencies:
    required: false
    description:
     - A list of services upon which this application depends.

  healthChecks:
    required: false
    description:
     - An array of checks to be performed on running tasks to determine if they are operating as expected.

  backoffSeconds:
    required: false
    description:
     - Configures exponential backoff behavior when launching potentially sick apps. The backoff period is multiplied by the factor for each consecutive failure until it reaches maxLaunchDelaySeconds.

  backoffFactor:
    required: false
    description:
     - Configures exponential backoff behavior when launching potentially sick apps. The backoff period is multiplied by the factor for each consecutive failure until it reaches maxLaunchDelaySeconds.

  maxLaunchDelaySeconds:
    required: false
    description:
     - Configures exponential backoff behavior when launching potentially sick apps. The backoff period is multiplied by the factor for each consecutive failure until it reaches maxLaunchDelaySeconds.

  upgradeStrategy_minimumHealthCapacity:
    required: false
    description:
     - a number between 0and 1 that is multiplied with the instance count. This is the minimum number of healthy nodes that do not sacrifice overall application purpose.

  upgradeStrategy_maximumOverCapacity:
    required: false
    description:
     - a number between 0 and 1 which is multiplied with the instance count. This is the maximum number of additional instances launched at any point of time during the upgrade process.

  force:
    required: false
    description:
     - If the app is affected by a running deployment, then the update operation will fail. The current deployment can be overridden by setting the `force` query parameter. Default: false.

  waitTimeout:
    required: false
    description:
     - If set and the operation is create or update, wait for the application to become available until timeout seconds.

author: "Ludovic Claude (@ludovicc)"
"""

EXAMPLES = """
TODO
# Create a new issue and add a comment to it:
- name: Create an issue
  jira: uri={{server}} username={{user}} password={{pass}}
        project=ANS operation=create
        summary="Example Issue" description="Created using Ansible" issuetype=Task
  register: issue

- name: Comment on issue
  jira: uri={{server}} username={{user}} password={{pass}}
        issue={{issue.meta.key}} operation=comment 
        comment="A comment added by Ansible"

# Assign an existing issue using edit
- name: Assign an issue using free-form fields
  jira: uri={{server}} username={{user}} password={{pass}}
        issue={{issue.meta.key}} operation=edit
        assignee=ssmith

# Create an issue with an existing assignee
- name: Create an assigned issue
  jira: uri={{server}} username={{user}} password={{pass}}
        project=ANS operation=create
        summary="Assigned issue" description="Created and assigned using Ansible" 
        issuetype=Task assignee=ssmith

# Edit an issue using free-form fields
- name: Set the labels on an issue using free-form fields
  jira: uri={{server}} username={{user}} password={{pass}}
        issue={{issue.meta.key}} operation=edit 
  args: { fields: {labels: ["autocreated", "ansible"]}}

- name: Set the labels on an issue, YAML version
  jira: uri={{server}} username={{user}} password={{pass}}
        issue={{issue.meta.key}} operation=edit 
  args: 
    fields: 
      labels:
        - "autocreated"
        - "ansible"
        - "yaml"

# Retrieve metadata for an issue and use it to create an account
- name: Get an issue
  jira: uri={{server}} username={{user}} password={{pass}}
        project=ANS operation=fetch issue="ANS-63"
  register: issue

- name: Create a unix account for the reporter
  sudo: true
  user: name="{{issue.meta.fields.creator.name}}" comment="{{issue.meta.fields.creator.displayName}}"

# Transition an issue by target status
- name: Close the issue
  jira: uri={{server}} username={{user}} password={{pass}}
        issue={{issue.meta.key}} operation=transition status="Done"
"""

import json
import base64
import time

def request(url, user=None, passwd=None, data=None, method=None):
    if data:
        data = json.dumps(data)

    if not user:
      auth = base64.encodestring('%s:%s' % (user, passwd)).replace('\n', '')
      response, info = fetch_url(module, url, data=data, method=method, 
                               headers={'Content-Type':'application/json',
                                        'Authorization':"Basic %s" % auth})
    else:
      response, info = fetch_url(module, url, data=data, method=method, 
                               headers={'Content-Type':'application/json'})

    if info['status'] not in (200, 204):
        module.fail_json(msg=info['msg'])

    body = response.read()

    if body:
        return json.loads(body)
    else:
        return {}

def tryRequest(url, user=None, passwd=None, data=None, method=None):
    if not user:
      auth = base64.encodestring('%s:%s' % (user, passwd)).replace('\n', '')
      response, info = fetch_url(module, url, data=data, method=method,
                               headers={'Content-Type':'application/json',
                                        'Authorization':"Basic %s" % auth})
    else:
      response, info = fetch_url(module, url, data=data, method=method,
                               headers={'Content-Type':'application/json'})

    body = {}

    if info['status'] in (200, 204):
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

def delete(url, user, passwd):
    return request(url, user, passwd, data=None, method='DELETE')

def create(restbase, user, passwd, params):
    data = {'id': params['id']}

    # Merge in any additional or overridden fields
    for arg in ['cmd', 'args', 'cpus', 'mem', 'ports', 'requirePorts', 'instances', 'executor', 'container', 'env', 'constraints', 'acceptedResourceRoles', 'labels', 'uris', 'dependencies', 'healthChecks', 'backoffFactor', 'backoffSeconds', 'maxLaunchDelaySeconds', 'upgradeStrategy']:
    	if params[arg]:
    		data.update({arg: params[arg]})

    url = restbase + '/apps'

    ret = post(url, user, passwd, data)

    if params['waitTimeout']:
      waitForDeployment(restbase, user, passwd, params, ret['deployments'][0]['id'])

    return ret

def edit(restbase, user, passwd, params):
    data = {'id': params['id']}

    # Merge in any additional or overridden fields
    for arg in ['cmd', 'args', 'cpus', 'mem', 'ports', 'requirePorts', 'instances', 'executor', 'container', 'env', 'constraints', 'acceptedResourceRoles', 'labels', 'uris', 'dependencies', 'healthChecks', 'backoffFactor', 'backoffSeconds', 'maxLaunchDelaySeconds', 'upgradeStrategy']:
    	if params[arg]:
    		data.update({arg: params[arg]})

    url = restbase + '/apps/' + params['id'] + '?force=' + str(params['force']).lower()

    ret = put(url, user, passwd, data)

    if params['waitTimeout']:
      waitForDeployment(restbase, user, passwd, params, ret['deploymentId'])

    return ret

def waitForDeployment(restbase, user, passwd, params, deploymentId):
  timeout = time.time() + params['waitTimeout']

  while True:
    url = restbase + '/deployments'
    deployments, info = tryRequest(url, user, passwd)

    if info['status'] in (200, 204):
      deploymentIds = map(lambda x: x['id'], deployments)
      if deploymentId not in deploymentIds:
        return

    time.sleep(1)

    if time.time() > timeout:
      module.fail_json(msg='Timeout waiting for deployment.')


def restart(restbase, user, passwd, params):
    data = {
        'force': params['force']
        }

    url = restbase + '/apps/' + params['id'] + '/restart'   

    ret = post(url, user, passwd, data) 

    return ret

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
    ret = delete(url, user, passwd) 
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
    ret = delete(url, user, passwd) 
    return ret

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
            state=dict(choices=['absent', 'present', 'restart', 'kill'], required=True),
            username=dict(required=False,default=None),
            password=dict(required=False,default=None),
            id=dict(type='str'),
            cmd=dict(aliases=['command'], type='str'),
            args=dict(aliases=['arguments'], type='list'),
            cpus=dict(type='float'),
            mem=dict(aliases=['memory']),
            ports=dict(type='list'),
            requirePorts=dict(default=False, type='bool'),
            instances=dict(),
            executor=dict(),
            container=dict(),
            docker_image=dict(),
            docker_forcePullImage=dict(default=False, type='bool'),
            docker_privileged=dict(default=False, type='bool'),
            docker_network=dict(default='none', type='str'),
            docker_parameters=dict(default=[]),
            docker_portMappings=dict(default=[]),
            container_volumes=dict(default=[]),
            env=dict(default={},type='dict'),
            constraints=dict(type='list'),
            acceptedResourceRoles=dict(),
            labels=dict(type='list'),
            uris=dict(type='list'),
            dependencies=dict(type='list'),
            healthChecks=dict(type='list'),
            backoffSeconds=dict(type='float'),
            backoffFactor=dict(type='float'),
            maxLaunchDelaySeconds=dict(type='float'),
            upgradeStrategy=dict(default={}),
            upgradeStrategy_minimumHealthCapacity=dict(),
            upgradeStrategy_maximumOverCapacity=dict(),
            force=dict(default=False, type='bool'),
            waitTimeout=dict(type='int')
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

    # Ensure that we use int values for port mappings
    if module.params['docker_portMappings']:
      mappings = module.params['docker_portMappings']
      mappings = [{k:int(v) for k,v in kv.iteritems()} for kv in mappings]
      module.params['docker_portMappings'] = mappings

    if module.params['docker_image'] and not module.params['container']:
    	module.params['container'] = { 'type': 'DOCKER', 'docker': { 'image': module.params['docker_image'], 'forcePullImage': bool(module.params['docker_forcePullImage']), 'privileged': bool(module.params['docker_privileged']), 'network': module.params['docker_network'], 'parameters': module.params['docker_parameters'], 'portMappings': module.params['docker_portMappings']}, 'volumes': module.params['container_volumes']}

    if module.params['upgradeStrategy_minimumHealthCapacity']:
    	module.params['upgradeStrategy'].update({'minimumHealthCapacity': module.params['upgradeStrategy_minimumHealthCapacity']})

    if module.params['upgradeStrategy_maximumOverCapacity']:
    	module.params['upgradeStrategy'].update({'maximumOverCapacity': module.params['upgradeStrategy_maximumOverCapacity']})

    if not uri.endswith('/'):
        uri = uri+'/'
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


    module.exit_json(changed=True, meta=ret)


from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
main()
