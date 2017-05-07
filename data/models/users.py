from pynamodb.attributes import UnicodeAttribute, UnicodeSetAttribute
from pynamodb.models import Model

from utils import generate_id


class User(Model):
    """
    A DynamoDB User
    """

    class Meta:
        table_name = 'User'
        region = 'us-east-1'

    username = UnicodeAttribute(hash_key=True)
    email = UnicodeAttribute()
    first_name = UnicodeAttribute()
    last_name = UnicodeAttribute()
    phone_number = UnicodeAttribute(null=True)
    user_id = UnicodeAttribute(range_key=True, default=generate_id)
    # user_id = UnicodeAttribute(hash_key=True)

    """
    The authoritative truth for membership of a user
    in either a team or as an individual in a resource
    is NOT managed here.

    This is simply a short list of resources and teams
    for which the user MAY or MAY NOT be a member.

    These caches must be invalidated and checked whenever
    a call is made regarding permissions or membership.
    """
    resource_cache = UnicodeSetAttribute(default=set())
    team_cache = UnicodeSetAttribute(default=set())

    @classmethod
    def get_user_by_username(self, username):
        for user in User.query(username):
	    return user

    @classmethod
    def get_user_by_userid(self, user_id):
        for user in User.scan(user_id__eq=user_id):
	    return user

    @classmethod
    def get_user_resources_by_username(self, username):
	for user in User.query(username):
	    return user.resource_cache

    @classmethod
    def get_user_list_for_resource(self, resource_id):
	user_list = []
	for user in User.scan():
	    if (user.resource_cache):
	        for resource in user.resource_cache:
	            if resource == resource_id:
	                user_list.append(user)
        return user_list

    def assign_team(self, team_id):
	self.team_cache.add(team_id);

    def invalidate_team(self, team_id):
	self.team_cache.remove(team_id);

    def to_dict(self):
        return dict(
            username=self.username,
            first_name=self.first_name,
            last_name=self.last_name,
            user_id=self.user_id,
            email=self.email)
