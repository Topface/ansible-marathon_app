from functools import partial

def needInt(a):
    return a in (
        "/ports[]",
        "/container/docker/portMappings[]/containerPort",
        "/container/docker/portMappings[]/hostPort",
        "/container/docker/portMappings[]/servicePort",
        "/healthChecks[]/portIndex",
        "/healthChecks[]/port",
        "/healthChecks[]/gracePeriodSeconds",
        "/healthChecks[]/maxConsecutiveFailures",
        "/healthChecks[]/intervalSeconds",
        "/healthChecks[]/timeoutSeconds",
        "/instances")

def needFloat(a):
    return a in (
        "/disk",
        "/cpus",
        "/mem")

def fix_named_type(name, a):

    if a is None:
        return a
    elif isinstance(a, dict):
        casted_dict = dict()
        for k,v in a.iteritems():
            casted_dict[k] = fix_named_type(name + "/" + k, v)
        return casted_dict
    elif isinstance(a, list):
        return map(partial(fix_named_type, name + "[]"), a)
    elif needInt(name):
        return int(a)
    elif needFloat(name): # and isinstance(a, basestring):
        return float(a)
    else:
        return a

def fix_marathon_types(a):
    return fix_named_type("", a)

class FilterModule(object):
    def filters(self):
        return {'fix_marathon_types': fix_marathon_types}
