from django.contrib.auth import logout

from .handlers import (
        get_password_hash,
        PASSWORD_HASH_KEY,
        update_session_auth_hash)


class CheckPasswordHash(object):
    """Logout user if value of hash key in session is not equal to current password hash
       If current user session has no the `PASSWORD_HASH_KEY` update it so we don't logout
       currently active users.
    """
    def process_view(self, request, *args, **kwargs):
        if getattr(request.user, 'is_authenticated') and request.user.is_authenticated():
            if request.session.get(PASSWORD_HASH_KEY) is None:
                update_session_auth_hash(request, request.user)
            if request.session.get(PASSWORD_HASH_KEY) != get_password_hash(request.user):
                logout(request)
