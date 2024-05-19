"""
JSON encoder that can convert Python objects into JSON, 
like datetime.datetime objects,
which are not natively serializable by the standard JSON encoder in Python.
"""
import datetime

now = datetime.datetime.utcnow()
class DTEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        else:
            return json.JSONEncoder.default(self, obj)
