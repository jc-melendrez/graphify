from django.contrib.auth.models import User
from firebase_admin import auth
from rest_framework import authentication
from rest_framework import exceptions

class FirebaseAuthentication(authentication.BaseAuthentication):
    """
    Custom authentication class for Django REST Framework using Firebase.
    Expects a 'Bearer <token>' in the Authorization header.
    """
    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header:
            return None

        id_token = auth_header.split(' ').pop()
        if not id_token:
            return None

        try:
            # Verify the token with Firebase Admin SDK
            decoded_token = auth.verify_id_token(id_token)
        except Exception as e:
            raise exceptions.AuthenticationFailed(f'Invalid Firebase token: {str(e)}')

        uid = decoded_token.get('uid')
        email = decoded_token.get('email')
        name = decoded_token.get('name', '')

        if not uid:
            raise exceptions.AuthenticationFailed('Firebase UID not found in token.')

        # Get or create the Django user
        try:
            user, created = User.objects.get_or_create(
                username=uid,
                defaults={
                    'email': email,
                    'first_name': name.split(' ')[0] if name else '',
                    'last_name': ' '.join(name.split(' ')[1:]) if ' ' in name else ''
                }
            )
            if created:
                user.set_unusable_password()
                user.save()
            return (user, None)
        except Exception as e:
            raise exceptions.AuthenticationFailed(f'User synchronization failed: {str(e)}')