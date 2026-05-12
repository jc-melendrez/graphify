import json
import logging
import random
import time
import secrets
import hashlib
import requests
import re
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django_ratelimit.decorators import ratelimit
from firebase_admin import auth, firestore
from django.contrib.auth.models import User
from django.contrib.auth import login, logout
from django.conf import settings
from django.contrib import messages
from django.core.mail import send_mail
from django.core.exceptions import ValidationError

# --- Security Helpers ---
def validate_email_format(email):
    """Validates email format using RFC 5322 simplified pattern."""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, email) is not None

def validate_password_strength(password):
    """Validates password meets minimum requirements."""
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")
    if not any(char.isdigit() for char in password):
        raise ValidationError("Password must contain at least one digit.")
    if not any(char.isupper() for char in password):
        raise ValidationError("Password must contain at least one uppercase letter.")
    # Special character requirement removed


# --- Views ---

@csrf_protect
@ratelimit(key='ip', rate='10/h', method='POST',block=False)
def login_page(request):

    if getattr(request, 'limited', False):
        messages.error(request, 'Too many login attempts. Please try again in an hour.')
        return render(request, 'authentication/login.html', {
            'firebase_config': json.dumps(settings.FIREBASE_PUBLIC_CONFIG)
        })

    """Handles both displaying the login page and processing login attempts."""
    if request.user.is_authenticated:
        return redirect('dashie')

    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        
        if not email or not password:
            messages.error(request, 'Email and password are required.')
            return render(request, 'authentication/login.html', {
                'firebase_config': json.dumps(settings.FIREBASE_PUBLIC_CONFIG)
            })
        
        try:
            firebase_user = auth.get_user_by_email(email)
            providers = [p.provider_id for p in firebase_user.provider_data]
            
            # THE FIX: Accurately report if BOTH accounts are linked!
            if ('google.com' in providers or 'github.com' in providers) and 'password' not in providers:
                if 'google.com' in providers and 'github.com' in providers:
                    messages.warning(request, 'This email is linked to BOTH Google and GitHub. Please use either sign-in button below.')
                elif 'google.com' in providers:
                    messages.warning(request, 'This email is linked to Google. Please use the Google sign-in button below.')
                else:
                    messages.warning(request, 'This email is linked to GitHub. Please use the GitHub sign-in button below.')
                
                return render(request, 'authentication/login.html', {
                    'firebase_config': json.dumps(settings.FIREBASE_PUBLIC_CONFIG)
                })

            api_key = settings.FIREBASE_PUBLIC_CONFIG.get('apiKey')
            
            if not api_key:
                messages.error(request, "Server Configuration Error: Firebase API Key is missing. Check your .env file.")
                return render(request, 'authentication/login.html', {
                    'firebase_config': json.dumps(settings.FIREBASE_PUBLIC_CONFIG)
                })

            verify_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            
            response = requests.post(verify_url, json=payload)
            
            if response.status_code != 200:
                error_data = response.json()
                error_msg = error_data.get('error', {}).get('message', 'UNKNOWN_ERROR')
                
                if error_msg == 'INVALID_LOGIN_CREDENTIALS':
                    messages.error(request, 'Invalid email or password.')
                else:
                    messages.error(request, f'Login failed: {error_msg}')
                    
                return render(request, 'authentication/login.html', {
                    'firebase_config': json.dumps(settings.FIREBASE_PUBLIC_CONFIG)
                })

            django_user, created = User.objects.get_or_create(
                username=firebase_user.uid,
                defaults={
                    'email': email,
                    'first_name': firebase_user.display_name.split(' ')[0] if firebase_user.display_name else '',
                    'last_name': ' '.join(firebase_user.display_name.split(' ')[1:]) if firebase_user.display_name and ' ' in firebase_user.display_name else ''
                }
            )
            
            login(request, django_user)
            return redirect('dashie')
            
        except auth.UserNotFoundError:
            messages.error(request, f'No account found for {email}. Please register.')
            return redirect('register')
        except Exception as e:
            logging.error(f"Login error: {e}")
            messages.error(request, 'Login failed. Please try again.')

    context = {
        'firebase_config': json.dumps(settings.FIREBASE_PUBLIC_CONFIG)
    }
    return render(request, 'authentication/login.html', context)

@csrf_protect
def otp_verify_view(request):
    """Verifies the OTP and activates the Firebase account."""
    reg_data = request.session.get('registration_data')
    if not reg_data:
        messages.error(request, "Session expired. Please try registering again.")
        return redirect('register')

    if request.method == 'POST':
        submitted_otp = request.POST.get('otp', '')
        
        if time.time() > reg_data.get('otp_expiry', 0):
            messages.error(request, "OTP has expired. Please register again.")
            _clear_registration_session(request)
            return redirect('register')
        
        submitted_otp_hash = hashlib.sha256(submitted_otp.encode()).hexdigest()
        stored_otp_hash = reg_data.get('otp_hash', '')
        
        if not secrets.compare_digest(submitted_otp_hash, stored_otp_hash):
            messages.error(request, "Invalid OTP. Please try again.")
            return render(request, 'authentication/verify_otp.html', {'email': reg_data.get('email')})
        
        try:
            uid = reg_data.get('uid')
            email = reg_data.get('email')
            
            if not uid or not email:
                messages.error(request, "Registration data corrupted. Please try again.")
                _clear_registration_session(request)
                return redirect('register')
            
            # --- THE FIX: MARK EMAIL AS VERIFIED ---
            auth.update_user(uid, disabled=False, email_verified=True)
            
            db = firestore.client()
            user_doc = db.collection('users').document(uid)
            user_doc.set({
                'email': email,
                'firebase_uid': uid,
                'providers': ['email'],
                'created_at': firestore.SERVER_TIMESTAMP
            })
            
            django_user, created = User.objects.get_or_create(
                username=uid,
                defaults={'email': email, 'first_name': '', 'last_name': ''}
            )
            django_user.set_unusable_password()
            django_user.save()
            
            _clear_registration_session(request)
            
            login(request, django_user)
            return redirect('dashie')
                
        except Exception as e:
            logging.error(f"Activation error: {str(e)}")
            messages.error(request, "Failed to activate account. Please try again.")
            return redirect('register')

    return render(request, 'authentication/verify_otp.html', {'email': reg_data.get('email')})
    
@csrf_exempt
@ratelimit(key='ip', rate='10/h', method='POST', block=False)
def google_login(request):

    if getattr(request, 'limited', False):
        return JsonResponse({"status": "error", "message": "Too many login attempts. Please try again later."}, status=429)

    """Handles Google OAuth authentication via Firebase - SECURE VERSION."""
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            id_token = data.get('id_token')

            if not id_token:
                return JsonResponse({"status": "error", "message": "ID token not provided."}, status=400)

            # Verify the ID token against Firebase
            decoded_token = auth.verify_id_token(id_token)
            firebase_uid = decoded_token.get('uid')
            email = decoded_token.get('email')
            name = decoded_token.get('name', '')

            if not email:
                return JsonResponse({"status": "error", "message": "Email not provided by Google."}, status=400)

            # Get or create Django user for session management
            django_user, created = User.objects.get_or_create(
                username=firebase_uid,
                defaults={
                    'email': email,
                    'first_name': name.split(' ')[0] if name else '',
                    'last_name': ' '.join(name.split(' ')[1:]) if ' ' in name else ''
                }
            )

            if created or django_user.has_usable_password():
                django_user.set_unusable_password()
                django_user.save()

            # Store user data in Firestore
            db = firestore.client()
            user_doc = db.collection('users').document(firebase_uid)
            user_doc.set({
                'email': email,
                'name': name,
                'firebase_uid': firebase_uid,
                'providers': firestore.ArrayUnion(['google']),
                'last_login': firestore.SERVER_TIMESTAMP
            }, merge=True)

            login(request, django_user)
            return JsonResponse({"status": "success"})
        except Exception as e:
            logging.error(f"Google login error: Authentication failed")
            return JsonResponse({"status": "error", "message": "Authentication failed. Please try again."}, status=401)
            
    return JsonResponse({"status": "error", "message": "Method not allowed"}, status=405)


def logout_view(request):
    """Logs the user out and redirects to the login page."""
    logout(request)
    return redirect('login')


@csrf_exempt
@ratelimit(key='ip', rate='10/h', method='POST', block=False)
def github_login(request):

    if getattr(request, 'limited', False):
        return JsonResponse({"status": "error", "message": "Too many login attempts. Please try again later."}, status=429)

    """Handles Firebase GitHub authentication token verification."""
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            id_token = data.get('id_token')

            if not id_token:
                return JsonResponse({"status": "error", "message": "ID token not provided."}, status=400)

            # Verify the Firebase token
            decoded_token = auth.verify_id_token(id_token)
            firebase_uid = decoded_token.get('uid')
            email = decoded_token.get('email')
            name = decoded_token.get('name', '')

            if not email:
                return JsonResponse({"status": "error", "message": "Email not provided by GitHub."}, status=400)

            # Get or create Django user for session management
            django_user, created = User.objects.get_or_create(
                username=firebase_uid,
                defaults={
                    'email': email,
                    'first_name': name.split(' ')[0] if name else '',
                    'last_name': ' '.join(name.split(' ')[1:]) if ' ' in name else ''
                }
            )

            if created or django_user.has_usable_password():
                django_user.set_unusable_password()
                django_user.save()

            # Update Firestore
            db = firestore.client()
            user_doc = db.collection('users').document(firebase_uid)
            user_doc.set({
                'email': email,
                'name': name,
                'firebase_uid': firebase_uid,
                'providers': firestore.ArrayUnion(['github']),
                'last_login': firestore.SERVER_TIMESTAMP
            }, merge=True)

            login(request, django_user)
            return JsonResponse({"status": "success"})

        except Exception as e:
            logging.error(f"GitHub verification error: {str(e)}")
            return JsonResponse({"status": "error", "message": "Authentication failed. Please try again."}, status=401)

    return JsonResponse({"status": "error", "message": "Method not allowed"}, status=405)


@csrf_protect
@ratelimit(key='ip', rate='5/h', method='POST', block=False)
def register_view(request):
    if getattr(request, 'limited', False):
        messages.error(request, 'Too many registration attempts. Please try again later.')
        return render(request, 'authentication/register.html')
    """Handles user registration and sending OTP - MAXIMUM SECURITY VERSION."""
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        password_conf = request.POST.get('password_conf', '')

        if not email or not validate_email_format(email):
            messages.error(request, "Please enter a valid email address.")
            return render(request, 'authentication/register.html')

        if not password or password != password_conf:
            messages.error(request, "Passwords must be provided and match.")
            return render(request, 'authentication/register.html')
        
        try:
            validate_password_strength(password)
        except ValidationError as e:
            messages.error(request, str(e))
            return render(request, 'authentication/register.html')

        # SECURE WORKFLOW: Check for existing users
        try:
            existing_user = auth.get_user_by_email(email)
            if not existing_user.disabled:
                # Active user already exists
                messages.error(request, "An account with this email already exists. Please login instead.")
                return render(request, 'authentication/register.html')
            else:
                # Found a previous abandoned registration. Delete it so we can start fresh.
                auth.delete_user(existing_user.uid)
        except auth.UserNotFoundError:
            pass # No user found, proceed normally
        except Exception as e:
            logging.error("Firebase lookup error")
            messages.error(request, "Registration service temporarily unavailable.")
            return render(request, 'authentication/register.html')

        # 1. CREATE USER IN FIREBASE IMMEDIATELY AS DISABLED
        # Firebase hashes the password right now. Django stores NOTHING.
        try:
            firebase_user = auth.create_user(
                email=email,
                password=password,
                disabled=True  # <--- THIS IS THE SECURITY KEY
            )
        except Exception as e:
            messages.error(request, "Failed to create account. Please try again.")
            return render(request, 'authentication/register.html')

        # 2. Generate OTP
        otp = str(random.randint(100000, 999999))
        otp_hash = hashlib.sha256(otp.encode()).hexdigest()
        
        # 3. Store ONLY the Firebase UID and OTP hash in the session
        request.session['registration_data'] = {
            'uid': firebase_user.uid,
            'email': email,
            'otp_hash': otp_hash,
            'otp_expiry': time.time() + 300,
        }
        request.session.modified = True

        # 4. Send OTP email
        try:
            send_mail(
                'Your Graphify Verification Code',
                f'Welcome to Graphify! Your one-time password is: {otp}\n\nThis code expires in 5 minutes.',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            messages.success(request, f"A verification code has been sent to {email}.")
            return redirect('verify_otp')
        except Exception as e:
            logging.error("Email send failed")
            auth.delete_user(firebase_user.uid) # Rollback Firebase creation if email fails
            messages.error(request, "Failed to send verification code. Please try again.")
            return render(request, 'authentication/register.html')

    return render(request, 'authentication/register.html')
