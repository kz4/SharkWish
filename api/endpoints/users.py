import requirements
import json
from data.models.users import User
from data.authentication import *
from common.http import *
from common.api_call import *
from common.velo_exception import *

SUCCESS = 200

"""
More testable endpoint?
def object_oriented_add_user(event, context):
    api_call = AddUser(event, context)
    add_user.run()
"""

class TokenValidate(ApiCall):

    def __init__(self,event,context):
        self.event = event
        self.context = context
        debug('TokenValidate', 'event is: {}'.format(self.event))

    def parse(self):
        self.post_body = get_event_value(self.event, key='body')

        if not self.post_body:
            return('missing bad post body')

        debug('TokenValidate', 'post body is: {}'.format(self.post_body))

        self.access_token = self.post_body.get('access_token')

    def validate(self):
        if not self.access_token: raise ValidateException("Missing access token")

    def run(self):
        status = valid_token(self.access_token)
        if status == SUCCESS:
            return success()
        else:
            return error()

class LogoutUser(ApiCall):

    def __init__(self,event,context):
        self.event = event
        self.context = context
        debug('LogoutUser', 'event is: {}'.format(self.event))

    def parse(self):
        self.post_body = get_event_value(self.event, key='body')

        if not self.post_body:
            return('missing bad post body')

        debug('LogoutUser', 'post body is: {}'.format(self.post_body))

        self.access_token = self.post_body.get('access_token')

    def validate(self):
        if not self.access_token: raise ValidateException("Missing access token")

    def run(self):
        status = logout(self.access_token)
        if status == SUCCESS:
            return success('User logged out successfully')
        else:
            return error()


class RefreshUser(ApiCall):

    def __init__(self,event,context):
        self.event = event
        self.context = context
        debug('RefreshUser', 'event is: {}'.format(self.event))

    def parse(self):
        self.post_body = get_event_value(self.event, key='body')

        if not self.post_body:
            return error('missing/bad post body')

        debug('RefreshUser', 'post body is: {}'.format(self.post_body))

        self.refresh_token = self.post_body.get('refresh_token')
        self.user_id = self.post_body.get('user_id')

    def validate(self):
        if not self.refresh_token: raise ValidateException("Missing refresh token")
        if not self.user_id: raise ValidateException("Missing user_id")

    def run(self):

        user = User.get_user_by_userid(self.user_id)

        if not user:
            return not_found('user_id {} not found'.format(self.user_id) )

        identity_token, access_token = refresh_tokens(self.refresh_token)

        if identity_token and access_token:
            response = dict(identity_token=identity_token,access_token=access_token)
            return success(response)
        else:
            return error("Error refreshing tokens")

class AddUser(ApiCall):
    def __init__(self, event, context):
        self.event = event
        self.context = context
        debug('ADD_USER_INIT', 'event is: {}'.format(self.event))

    def parse(self):
        self.post_body = get_event_value(self.event, key='body')

        if not self.post_body:
            return error('missing/bad post body')
        debug('ADD_USER_PARSE', 'post body is: {}'.format(self.post_body))

        self.username = self.post_body.get('username')
        self.password = self.post_body.get('password')
        self.email = self.post_body.get('email')

    def validate(self):
        # validates the values INSIDE the event
        # maybe there's a better way to do this
        # using the User model class? Some .validate() method?
        if not self.username: raise ValidateException("username is None")
        if not self.email: raise ValidateException("email is None")
        if not self.password: raise ValidateException("password is None")
        debug('ADD_USER_VALIDATE', 'Validating attributes are not null')

    def run(self):
        # may be an opportunity to FURTHER abstract out this run step.
        # even if just for AddUser().
        # add to user pool:
        ok = sign_up_user(self.username, self.password, self.email)
        if not ok:
            return error("Unable to add User")

        # TODO: Implement confirm endpoint/ui flow, then delete
        ok = admin_confirm_signup(self.username)
        if not ok:
            d = admin_delete_user(self.username)
            if not d:
                return error("Unable to delete User from user pool")
            return error("Unable to confirm User")

        new_user = User()
        new_user.username = self.username
        new_user.email = self.email
        new_user.first_name = self.post_body.get('first_name')
        new_user.last_name = self.post_body.get('last_name')
        new_user.phone_number = self.post_body.get('phone_number')
        new_user.organization = self.post_body.get('organization')
        print new_user.organization

        try:
            new_user.save()
        except Exception as e:
            ok = admin_delete_user(self.username)
            if not ok:
                return error("Unable to delete User from user pool")
            return error("Error creating new User: {}".format(e))

        debug("ADD_USER", "SUCCESS!")
        return success('User created!')

class SignUpUser(ApiCall):
    def __init__(self, event, context):
        self.event = event
        self.context = context
        debug('SIGNUP_USER_INIT', 'event is: {}'.format(self.event))

    def parse(self):
        self.post_body = get_event_value(self.event, key='body')

        if not self.post_body:
            return error('missing/bad post body')
        debug('SIGNUP_USER_PARSE', 'post body is: {}'.format(self.post_body))

        self.username = self.post_body.get('username')
        self.password = self.post_body.get('password')
        self.email = self.post_body.get('email')

    def validate(self):
        # validates the values INSIDE the event
        # maybe there's a better way to do this
        # using the User model class? Some .validate() method?
        if not self.username: raise ValidateException("username is None")
        if not self.email: raise ValidateException("email is None")
        if not self.password: raise ValidateException("password is None")
        debug('SIGNUP_USER_VALIDATE', 'Validating attributes are not null')

    def run(self):
        res = sign_up_user(self.username, self.password, self.email)
        if not res[0]:
            return error("Unable to add User: {}".format(res[1]))

        new_user = User()
        # new_user.user_id = self.username
        new_user.username = self.username
        new_user.email = self.email
        new_user.first_name = self.post_body.get('first_name')
        new_user.last_name = self.post_body.get('last_name')
        new_user.phone_number = self.post_body.get('phone_number')
        new_user.organization = self.post_body.get('organization')
        print new_user.organization


        try:
            new_user.save()
        except Exception as e:
            ok = admin_delete_user(self.username)
            if not ok:
                return error("Unable to delete User from user pool")
            return error("Error creating new User: {}".format(e))

        debug("SIGNUP_USER", "SUCCESS!")
        return success('User signed up, check your email for confirmation code!')

class ValidateUser(ApiCall):
    def __init__(self, event, context):
        self.event = event
        self.context = context
        debug('VALIDATE_USER_INIT', 'event is: {}'.format(self.event))

    def parse(self):
        self.post_body = get_event_value(self.event, key='body')
        if not self.post_body:
            return error('missing/bad post body')
        debug('VALIDATE_USER_PARSE', 'post body is: {}'.format(self.post_body))

        self.username = self.post_body.get('username')
        self.confirm_code = self.post_body.get('confirm_code')

    def validate(self):
        # validates the values INSIDE the event
        # maybe there's a better way to do this
        # using the User model class? Some .validate() method?
        if not self.username: raise ValidateException("username is None")
        if not self.confirm_code: raise ValidateException("confirm_code is None")
        debug('VALIDATE_USER_VALIDATE', 'Validating attributes are not null')

    def run(self):
        debug('test', self.username + ' ' + self.confirm_code)
        res = validate_user_on_aws(self.username, self.confirm_code)
        if not res[0]:
            try:
                user = User.query(self.username, limit=1).next()
                user.delete()
                ok = admin_delete_user(self.username)
                if not ok:
                    return error("Unable to delete User from user pool")
                return error("Unable to validate User: {}".format(res[1]))
            except StopIteration:
                return not_found("User not found in dynamodb")
            except Exception as e:
                return error(e)

        debug("VALIDATE_USER", "SUCCESS!")
        user_id = User.get_user_by_username(self.username).user_id
        resp = dict(
            validated = True,
            username = self.username,
	    user_id = user_id)
        return success(resp)

class GetUser(ApiCall):
    def __init__(self, event, context):
        self.event = event
        self.context = context
        debug('GET_USER_INIT', 'event is: {}'.format(self.event))

    def parse(self):
        self.path_param = get_event_value(self.event, key='pathParameters')

        if not self.path_param:
            return error('missing/invalid path parameters')
        debug('GET_USER_PARSE', 'path parameter is: {}'.format(self.path_param))

        self.username = self.path_param.get('username')

    def validate(self):
        # validates the values INSIDE the event
        # maybe there's a better way to do this
        # using the User model class? Some .validate() method?
        if not self.username: raise ValidateException("username is None")
        debug('GET_USER_VALIDATE', 'Validating attributes are not null')

    def run(self):
        try:
            user = User.query(self.username, limit=1).next()
        except StopIteration:
            return not_found()
        except Exception as e:
            return error(e)

	    debug("GET_USER", "SUCCESS!")
        return success(user.to_dict())

class GetUserList(ApiCall):
    def __init__(self, event, context):
        self.event = event
        self.context = context
        debug('GET_USER_LIST_INIT', 'event is: {}'.format(self.event))

    def parse(self):
        self.post_body = get_event_value(self.event, key='body')

        if not self.post_body:
            return error('missing/bad post body')
        debug('GET_USER_LIST_PARSE', 'post body is: {}'.format(self.post_body))

        self.users = self.post_body.get('users')

    def validate(self):
        # validates the values INSIDE the event
        # maybe there's a better way to do this
        # using the User model class? Some .validate() method?
        if not self.users: raise ValidateException("users is None")
        debug('GET_USER_VALIDATE', 'Validating attributes are not null')

    def run(self):
	user_list = []
	for user in self.users:
            try:
                user = User.query(user, limit=1).next()
		user_list.append(user.user_id)
            except StopIteration:
                return not_found()
            except Exception as e:
                return error(e)

	debug("GET_USER_lIST", "SUCCESS!")
        return success(user_list)

class ListUser(ApiCall):
    def __init__(self, event, context):
        self.event = event
        self.context = context
        debug('LIST_USER_INIT', 'event is: {}'.format(self.event))

    def parse(self):
        pass

    def validate(self):
        pass

    def run(self):
        all_users = []
        try:
            users = User.scan()
            for user in users:
                all_users.append(user.to_dict())
        except Exception as e:
            return error("Error listing all users {}".format(e))
        return success(all_users)

class ResendCode(ApiCall):
    def __init__(self, event, context):
        self.event = event
        self.context = context
        debug('RESEND_USER_CONFIRMATION_CODE_INIT', 'event is: {}'.format(self.event))

    def parse(self):
        params = get_event_value(self.event, 'pathParameters')
        debug('RESEND_USER_CONFIRMATION_CODE_PARSE', 'params is: {}'.format(params))
        if not params:
            return error("Invalid parameters")

        self.username = params.get('username')

    def validate(self):
        if not self.username: raise ValidateException("username is None")
        debug('RESEND_USER_CONFIRMATION_CODE_VALIDATE', 'Validating attributes are not null')

    def run(self):
        try:
            debug('RESEND_USER_CONFIRMATION_CODE_RUN', self.username)
            result, resp = resend_confirmation_code(self.username)

            if result:
                debug("RESEND_USER_CONFIRMATION_CODE_RUN_RESPONSE", resp)
                return success('Confirmation code resent!')
            else:
                return error("Failed to resend confirmation code: {}".format(resp))
        except Exception as e:
            return error("Failed to resend confirmation code: {}".format(e))

class ConfirmForgotPassword(ApiCall):
    def __init__(self, event, context):
        self.event = event
        self.context = context
        debug('CONFIRM_FORGOT_PASSWORD_INIT', 'event is: {}'.format(self.event))

    def parse(self):
        self.post_body = get_event_value(self.event, key='body')

        if not self.post_body:
            return error('missing/bad post body')
        debug('CONFIRM_FORGOT_PASSWORD_PARSE', 'post body is: {}'.format(self.post_body))

        self.username = self.post_body.get('username')
        self.password = self.post_body.get('password')
        self.confirmation_code = self.post_body.get('confirmationCode')

    def validate(self):
        if not self.username: raise ValidateException("username is None")
        if not self.confirmation_code: raise ValidateException("confirmation_code is None")
        if not self.password: raise ValidateException("password is None")
        debug('CONFIRM_FORGOT_PASSWORD_VALIDATE', 'Validating attributes are not null')

    def run(self):
        #print("confirmation_code: ", self.confirmation_code)
        ok = admin_confirm_forgot_password(self.username, self.confirmation_code, self.password)
        if not ok:
            return error("Unable to confirm forgot password from user pool")

        debug("CONFIRM_FORGOT_PASSWORD", "SUCCESS!")
        return success('User password changed successfully!')


def token_validate(event, context):
    api_call = TokenValidate(event, context)
    try:
        api_call.parse()
        api_call.validate()
    except Exception as e:
        return error(e.message)
    else:
        return api_call.run()

def logout_user(event, context):
    api_call = LogoutUser(event, context)
    try:
        api_call.parse()
        api_call.validate()
    except Exception as e:
        return error(e.message)
    else:
        return api_call.run()

def refresh_user(event, context):
    api_call = RefreshUser(event, context)
    try:
        api_call.parse()
        api_call.validate()
    except Exception as e:
        return error(e.message)
    else:
        return api_call.run()

def add_user(event, context):
    api_call = AddUser(event, context)
    try:
        api_call.parse()
        api_call.validate()
    except Exception as e:
        return error(e.message)
    else:
        return api_call.run()

def signup_user(event, context):
    api_call = SignUpUser(event, context)
    try:
        api_call.parse()
        api_call.validate()
    except Exception as e:
        return error(e.message)
    else:
        return api_call.run()

def validate_user(event, context):
    api_call = ValidateUser(event, context)
    try:
        api_call.parse()
        api_call.validate()
    except Exception as e:
        return error(e.message)
    else:
        return api_call.run()

def get_user(event, context):
    api_call = GetUser(event, context)
    try:
        api_call.parse()
        api_call.validate()
    except Exception as e:
        return error(e.message)
    else:
        return api_call.run()

def get_user_list(event, context):
    api_call = GetUserList(event, context)
    try:
        api_call.parse()
        api_call.validate()
    except Exception as e:
        return error(e.message)
    else:
        return api_call.run()

def list_user(event, context):
    api_call = ListUser(event, context)

    try:
        api_call.parse()
        api_call.validate()
    except Exception as e:
        return error(e.message)
    else:
        return api_call.run()

# def delete_user(event, context):
#     debug('DELETE_USER', 'event is: {}'.format(event))

#     post_body = get_event_value(event, 'pathParameters')

#     params = get_event_value(event, 'pathParameters')
#     if not params:
#         return error("Invalid path")

#     username = params.get('username')

#     # delete user from dynamodb
#     # del from dynamo first incase deletion error
#     try:
#         user = User.get_user_by_username(username)
#         if user is None:
#             return not_found("user does not exist")

#         for resource_id in user.resource_cache:
#             print "deleting user from resource: ",resource_id
#             resource = Resource.getResourceById(resource_id)
#             PermissionService().revoke_permissions(user, resource)

#         for team_id in user.team_cache:
#             print "deleting user from teams"
#             team = TeamModel.get_team_by_id(team_id)
#             team.remove_user(user.user_id)

#         user.delete()
#     except Exception as e:
#         return error(e)

#     # delete user from userpool
#     ok = admin_delete_user(username)
#     if not ok:
#         return error("Unable to delete User from user pool")

#     return success('User deleted')

def forgot_password(event, context):
    debug('FORGOT_PASSWORD', 'event is: {}'.format(event))
    post_body = get_event_value(event, 'pathParameters')
    params = get_event_value(event, 'pathParameters')
    if not params:
        return error("Invalid path")

    username = params.get('username')

    try:
        user = User.query(username, limit=1).next()
    except StopIteration:
        return not_found()
    except Exception as e:
        return error(e)

    # call forgot_password
    ok = admin_forgot_password(username)
    if not ok:
        return error("Unable to retrieve data from user pool")

    return success('User has been sent a verification code')

def confirm_forgot_password(event, context):
    api_call = ConfirmForgotPassword(event, context)
    try:
        api_call.parse()
        api_call.validate()
    except Exception as e:
        return error(e.message)
    else:
        return api_call.run()

def update_user(event, context):
    debug('UPDATE_USER', 'event is: {}'.format(event))

    post_body = get_event_value(event, key='body')

    if not post_body:
        return error('missing/bad post body')
    debug('UPDATE_USER', 'post body is: {}'.format(post_body))

    params = get_event_value(event, 'pathParameters')
    debug('UPDATE_USER', 'params is: {}'.format(params))
    if not params:
        return error("Invalid parameters")

    username = params.get('username')

    try:
        user = User.query(username, limit=1).next()
        debug('UPDATE_USER', 'user is: {}'.format(user))

        attributes = {}
        for key, value in post_body.items():
            setattr(user, key, value)

        user.save()
    except StopIteration:
        return not_found()
    except Exception as e:
        return error(e)

    return success(user.to_dict())

def resend(event, context):
    api_call = ResendCode(event, context)

    try:
        api_call.parse()
        api_call.validate()
    except Exception as e:
        return error(e.message)
    else:
        return api_call.run()
