import json
from logging import debug

CORS_HEADERS = {
    "Access-Control-Allow-Origin" : "*",
    "Access-Control-Allow-Credentials" : True
}

def respond(status, body, headers={}, cors=True):
    response_body = json.dumps(body, default=str)
    response = {
        "statusCode": status,
        "headers": CORS_HEADERS,
        "body": response_body,
    }
    return response

def success(body={}):
    return respond(200, body)

def updated(body={}):
    return respond(201, body)

def error(body=None, headers=None):
    return respond(500, body, headers)

def not_found(body=None, headers=None):
    return respond(404, body, headers)

def noauth(body=None):
    if not body:
        body = "Invalid Credentials"
    return respond(403, body)

def parse_event(raw_event):
    # invoking locally gives me a real dict.
    # invoking remotely yields a json, string
    # so handling this here for dev.
    if isinstance(raw_event, dict):
        return raw_event

    try:
        return json.loads(raw_event)
    except Exception as e:
        debug('EVENT PARSER', 'unable to parse event: {}'.format(e))
        return None

def get_event_value(raw_event, key=None):
    parsed_event =  parse_event(raw_event)
    if not parsed_event:
        debug('get_body', 'no event object')
        return None

    if not key:
        return parsed_event

    try:
        value = parsed_event[key]

        # this is stupid, serverless thing
        if isinstance(value, dict):
            return value
        return json.loads(value)
    except Exception as e:
        debug('decode_event', 'unable to parse event: {}'.format(e))
        return None
