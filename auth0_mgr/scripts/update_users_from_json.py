import sys
import json
import logging
from auth0_mgr.users.user_manager import UserManager

logger = logging.getLogger(__name__)

def main(argv):

    if len(argv) == 1:
        filename = argv[1]
    else:
        filename = "users.json"
        
    mgr = UserManager()

    with open(filename, 'r') as f:
        user_list = json.loads(f.read())

    #handle django export
    try:
        django_users = [x['fields'] for x in user_list]
        user_list = django_users
    except Exception:
        pass

    for user_data in user_list:
        if user_data.get('email'):
            try:
                user = mgr.get_user_by_email(user_data["email"])
                if user:
                    mgr.update_user_data(user, user_data)
                    logger.info("User %s updated in Auth0", (user_data.get('email'), ))
            except Exception as ex:
                logger.exception(ex)



if __name__ == "__main__":
   main(sys.argv[1:])