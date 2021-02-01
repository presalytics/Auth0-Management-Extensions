import logging
import typing
from auth0_mgr.models.user import Auth0User
from auth0_mgr.tokens import AdminTokenMgr


class UserManager(AdminTokenMgr):
    IDENTIFIER_FIELDS = [
        'username',
        'email'
    ]

    def __init__(self, *args, **kwargs):
        super(UserManager, self).__init__(*args, **kwargs)

    def get_user_by_email(self, email):
        """
        Returns and auth0 user that
        """
        users = self.auth0.users_by_email.search_users_by_email(email)
        if len(users) == 0:
            raise KeyError('email')
        if len(users) > 1:
            raise ValueError('More than one user with this email')
        return users[0]

    def update_user_data(self, user: typing.Union[typing.Dict, Auth0User], data={}, update_identifiers=False):  #
        """
        Pushes changed data on a in a user profile to auth0
        """
        auth0_user: Auth0User

        if isinstance(user, Auth0User):  # type: ignore
            auth0_user = user  # type: ignore
        else:
            auth0_user = Auth0User.load(**user)  # type: ignore
        auth0_user.load_data(data)
        dct = auth0_user.to_dict()
        user_id  = auth0_user.user_id
        if not update_identifiers:
            for key in self.IDENTIFIER_FIELDS:
                dct.pop(key, None)
        return self.auth0.users.update(user_id, dct)
    
    def assign_user_data(user_instance, user_data, override_existing=False):
        for key, val in user_data.items():
            if key == "user_metadata" or key == "app_metadata":
                metadata = user_data[key]
                for mkey, mval in metadata.items():
                    try:
                        if not hasattr(user_instance, mkey) or override_existing:
                            setattr(user_instance, mkey, mval)
                    except Exception:
                        logging.info("Could set attribute {} for user".format(mkey))
            else:
                try:    
                    if not hasattr(user_instance, key) or override_existing:
                        setattr(user_instance, key, val)
                except Exception:            
                    logging.info("Could set attribute {} for user".format(key))
        return user_instance

    def send_verification_email(self, user):
        user_id = user["user_id"]
        payload = {
            "user_id": user_id,
            "client_id": self.client_id
        }
        self.auth0.jobs.send_verification_email(payload)
