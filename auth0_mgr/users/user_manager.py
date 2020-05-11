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
        users = self.auth0.users_by_email.search_users_by_email(email)
        if len(users) == 0:
            raise KeyError('email')
        if len(users) > 1:
            raise ValueError('More than one user with this email')
        return users[0]

    def update_user_data(self, user, data={}, update_identifiers=False):
        user = Auth0User.load(**user)
        user.load_data(data)
        dct = user.to_dict()
        user_id  = user.user_id
        if not update_identifiers:
            for key in self.IDENTIFIER_FIELDS:
                dct.pop(key, None)
        self.auth0.users.update(user_id, dct)
        

