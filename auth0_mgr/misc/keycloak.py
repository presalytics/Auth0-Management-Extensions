import json
import typing
from auth0_mgr.tokens import AdminTokenMgr
from auth0_mgr.models.user import Auth0User

class UserImporter(AdminTokenMgr):
    def __init__(self, db_filename: str, *args, **kwargs):
        """
        Create migration file with commmand in jboss folder:
        bin/standalone.sh 
            -Djboss.socket.binding.port-offset=100 
            -Dkeycloak.migration.action=export 
            -Dkeycloak.migration.provider=singleFile 
            -Dkeycloak.migration.file=/tmp/keycloakdb.json
        """
        super(UserImporter, self).__init__(*args, **kwargs)
        self.db_file = db_filename

        with open(db_filename, 'r') as f:
            json_str = f.read()

        self.data = json.loads(json_str)
        self.users = []
        for user_data in self.data[1]["users"]:  # TODO: allow selection of realm users by realm name
            user = UserImporter.make_user_from_keycloak_data(user_data)
            if user:
                self.users.append(user)

    @staticmethod
    def make_user_from_keycloak_data(userdata: typing.Dict = None):

        if userdata:
            user_metadata = userdata.get("attributes", {})
            for key, val in user_metadata.items():
                try:
                    user_metadata[key] = str(val[0])
                except Exception:
                    pass
            
            name = userdata["firstName"] + " " + userdata["lastName"] if userdata.get("firstName", None) and userdata.get("lastName", None) else None
            # TODO:  convert credentials
            user = Auth0User(
                userdata.get("email", None),
                email_verified=userdata["emailVerified"],
                given_name=userdata.get("firstName", None),
                family_name=userdata.get("lastName", None),
                name=name,
                user_metadata=user_metadata
            )
            return user
        return None

    def to_file(self):
        users_dcts = [x.to_dict() for x in self.users]
        for dct in users_dcts:
            tmp = dict(dct)
            for key, val in tmp.items():
                if val is None:
                    dct.pop(key)
        with open("auth0_users.json", 'w+') as f:
            f.write(json.dumps(users_dcts))

    
    def push_users_to_auth0(self):
        conn = self.get_user_db_connection()
        for user in self.users:
            user_dict = user.to_dict()
            user_dict.update({
                "connection": conn["name"]
            })
            self.auth0.users.create(user_dict)


        

