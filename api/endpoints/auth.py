import requirements
from data.authentication import *
from common.http import *
from common.logging import debug
from common.api_call import *
from data.models.users import User
import json


def login(event, context):
    debug('LOGIN', 'event is: {}'.format(event))

    # get_body extracts the JSON event
    # and returns a python dict of the post body
    post_body = get_event_value(event, key='body')

    if not post_body:
        return error('missing/bad post body')
    debug('LOGIN', 'post body is: {}'.format(post_body))

    # if these don't exist, and we get None's
    # auth will fail regardless, no need to check.
    username = post_body.get('username')
    password = post_body.get('password')

    valid, refresh_token, access_token, id_token = authenticate_user(
            username, password)
    
    try:
        if valid:
            user_id = User.get_user_by_username(username).user_id
            if user_id:
                return success(body={
                    'refresh_token': refresh_token,
                    'access_token': access_token,
                    'id_token': id_token,
                    'username': username,
                    'user_id': user_id})
    except Exception as e:
        return noauth('{}'.format(e))

    return noauth()
