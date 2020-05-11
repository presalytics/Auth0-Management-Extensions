from environs import Env
from auth0.v3.authentication import GetToken
from auth0.v3.management import Auth0

env = Env()
env.read_env()

class AdminTokenMgr(object):
    def __init__(self, domain=None, client_id=None, client_secret=None, *args, **kwargs):
        self.domain = domain if domain else env.str('AUTH0_DOMAIN', None)
        self.client_id = client_id if client_id else env.str('AUTH0_CLIENT_ID', None)
        self.client_secret = client_secret if client_secret else env.str('AUTH0_CLIENT_SECRET')

        self.get_token = GetToken(self.domain)
        self.token_data = self.get_token.client_credentials(self.client_id, self.client_secret,'https://{}/api/v2/'.format(self.domain))
        self.mgmt_access_token = self.token_data['access_token']

        self.auth0 = Auth0(self.domain, self.mgmt_access_token)
        try:
            super(AdminTokenMgr, self).__init__(*args, **kwargs)
        except Exception:
            pass

    def get_user_db_connection(self):
        connections = self.auth0.connections.all()
        try:
            user_db = next(x for x in connections if "Username-Password-Authentication" in x["name"])
        except StopIteration:
            raise KeyError("Username-Password-Authentication")
        return user_db
    