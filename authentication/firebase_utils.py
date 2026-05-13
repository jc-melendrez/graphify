"""
Firebase Authentication Utilities

This module provides helper functions for Firebase Auth and Firestore operations.

ARCHITECTURE:
- Firebase Auth: Single source of truth for user authentication
  - Email/Password authentication
  - Google OAuth
  - GitHub OAuth (synced with Firebase)
  
- Firestore: User data storage
  - Document ID: Firebase UID (consistent across all auth methods)
  - Fields: email, name, providers (array), last_login, etc.
  
- Django User: Session management only
  - Username: Firebase UID (links to Firestore document)
  - Password: UNUSABLE for social/email auth (Firebase handles it)
  - Purpose: Maintain Django's session framework
"""

from firebase_admin import auth, firestore
import logging


def get_or_create_django_user(firebase_user):
    """
    Get or create a Django user from a Firebase user.
    
    Args:
        firebase_user: Firebase UserRecord object
        
    Returns:
        Django User object
    """
    from django.contrib.auth.models import User
    
    django_user, created = User.objects.get_or_create(
        username=firebase_user.uid,
        defaults={
            'email': firebase_user.email,
            'first_name': firebase_user.display_name.split(' ')[0] if firebase_user.display_name else '',
            'last_name': ' '.join(firebase_user.display_name.split(' ')[1:]) if firebase_user.display_name and ' ' in firebase_user.display_name else ''
        }
    )
    
    if created or django_user.has_usable_password():
        django_user.set_unusable_password()
        django_user.save()
    
    return django_user


def update_user_in_firestore(firebase_uid, data, merge=True):
    """
    Update user data in Firestore.
    
    Args:
        firebase_uid: Firebase user ID (document ID in Firestore)
        data: Dictionary of data to update
        merge: If True, merge with existing data; if False, overwrite
        
    Returns:
        Firestore write result
    """
    db = firestore.client()
    user_doc = db.collection('users').document(firebase_uid)
    return user_doc.set(data, merge=merge)


def get_user_from_firestore(firebase_uid):
    """
    Retrieve user data from Firestore.
    
    Args:
        firebase_uid: Firebase user ID
        
    Returns:
        Dictionary of user data or None if not found
    """
    db = firestore.client()
    user_doc = db.collection('users').document(firebase_uid).get()
    
    if user_doc.exists:
        return user_doc.to_dict()
    return None


def add_provider_to_user(firebase_uid, provider):
    """
    Add a new provider to a user's providers array.
    This allows users to link multiple auth methods to one account.
    
    Args:
        firebase_uid: Firebase user ID
        provider: Provider name ('google', 'github', 'email')
        
    Returns:
        Firestore write result
    """
    db = firestore.client()
    user_doc = db.collection('users').document(firebase_uid)
    return user_doc.update({
        'providers': firestore.ArrayUnion([provider]),
        'last_login': firestore.SERVER_TIMESTAMP
    })


def link_social_provider(email, provider, provider_data):
    """
    Link a social provider account to an existing Firebase user.
    
    Args:
        email: Email address to look up Firebase user
        provider: Provider name ('google' or 'github')
        provider_data: Dictionary of provider-specific data
        
    Returns:
        Firebase UID if successful, None if not found
    """
    try:
        firebase_user = auth.get_user_by_email(email)
        add_provider_to_user(firebase_user.uid, provider)
        
        # Update Firestore with provider-specific data
        firestore_data = {
            'last_login': firestore.SERVER_TIMESTAMP,
            'providers': firestore.ArrayUnion([provider])
        }
        firestore_data.update(provider_data)
        update_user_in_firestore(firebase_user.uid, firestore_data)
        
        return firebase_user.uid
    except auth.UserNotFoundError:
        logging.warning(f"No Firebase user found for email: {email}")
        return None
    except Exception as e:
        logging.error(f"Error linking provider: {e}")
        return None
