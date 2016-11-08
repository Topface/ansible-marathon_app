def force_to_int(a):
    if a is None or isinstance(a, (int, long)):
        return a
    elif isinstance(a, basestring):
        try:
            return int(a)
        except ValueError:
            return a
    elif isinstance(a, dict):
        casted_dict = dict()
        for k,v in a.iteritems():
            casted_dict[k] = force_to_int(v)
        return casted_dict
    elif isinstance(a, list):
        return map(force_to_int, a)
    else:
        return a

class FilterModule(object):
    def filters(self):
        return {'force_to_int': force_to_int}
