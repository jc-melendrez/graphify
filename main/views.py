import json
import logging
import random
import time
import requests
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from firebase_admin import auth
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.conf import settings
from django.urls import reverse
from django.contrib import messages
from django.core.mail import send_mail

def login_page(request):
    """Handles both displaying the login page and processing login attempts."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        try:
            firebase_user = auth.get_user_by_email(email)
            user = authenticate(request, username=email, password=password)
            if user is not None:
                login(request, user)
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid credentials. Please try again.')
        except auth.UserNotFoundError:
            user = authenticate(request, username=email, password=password)
            if user is not None:
                login(request, user)
                return redirect('dashboard')
            else:
                messages.warning(request, f'No account found for {email}. Please register.')
                return redirect('register')
        except Exception as e:
            logging.error(f"Login error: {e}")
            messages.error(request, 'Login failed. Please try again.')

    # Securely pass the config to the template
    context = {
        'firebase_config': json.dumps(settings.FIREBASE_PUBLIC_CONFIG)
    }
    return render(request, 'main/index.html', context)
@login_required
def dashboard_view(request):
    # The user object is automatically available in the template context
    # when using RequestContext, which is default.
    return render(request, 'main/dashboard.html')

@csrf_exempt
def google_login(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            id_token = data.get('id_token')

            # Verify the ID token against Firebase
            decoded_token = auth.verify_id_token(id_token)
            email = decoded_token.get('email')
            name = decoded_token.get('name', '')

            # Use email as the unique identifier for the Django user
            if not email:
                return JsonResponse({"status": "error", "message": "Email not provided by Google."}, status=400)

            # Get or create a Django user
            user, created = User.objects.get_or_create(
                username=email,
                defaults={
                    'email': email,
                    'first_name': name.split(' ')[0] if name else '',
                    'last_name': ' '.join(name.split(' ')[1:]) if ' ' in name else ''
                }
            )

            if created:
                user.set_unusable_password()
                user.save()

            # Store in Firestore
            from firebase_admin import firestore
            db = firestore.client()
            user_doc = db.collection('users').document(user.username)
            user_doc.set({
                'email': email,
                'name': name,
                'provider': 'google',
                'firebase_uid': decoded_token.get('uid'),
                'registered_at': firestore.SERVER_TIMESTAMP
            }, merge=True)  # merge to avoid overwriting

            # Log the user into Django's session framework
            login(request, user)

            return JsonResponse({"status": "success"})
        except Exception as e:
            logging.error(f"Google login error: {e}")
            return JsonResponse({"status": "error", "message": str(e)}, status=401)
            
    return JsonResponse({"status": "error", "message": "Method not allowed"}, status=405)

def logout_view(request):
    """Logs the user out and redirects to the login page."""
    logout(request)
    return redirect('login')

def github_login(request):
    """Redirects the user to GitHub's authorization page."""
    github_auth_url = (
        f"https://github.com/login/oauth/authorize?client_id={settings.GITHUB_CLIENT_ID}"
        f"&redirect_uri={request.build_absolute_uri(reverse('github_callback'))}"
        "&scope=user:email"
    )
    return redirect(github_auth_url)

def github_callback(request):
    """Handles the callback from GitHub after user authorization."""
    code = request.GET.get('code')
    if not code:
        return redirect('login')

    try:
        # 1. Exchange the code for an access token
        token_response = requests.post(
            'https://github.com/login/oauth/access_token',
            data={
                'client_id': settings.GITHUB_CLIENT_ID,
                'client_secret': settings.GITHUB_CLIENT_SECRET,
                'code': code,
            },
            headers={'Accept': 'application/json'}
        )
        token_response.raise_for_status()
        access_token = token_response.json().get('access_token')

        # 2. Use the access token to get user info
        user_response = requests.get(
            'https://api.github.com/user',
            headers={'Authorization': f'token {access_token}'}
        )
        user_response.raise_for_status()
        github_user_data = user_response.json()

        email = github_user_data.get('email')
        # If email is private, use the login as a fallback unique identifier
        username = github_user_data.get('login')
        name_str = github_user_data.get('name') or ''
        name = name_str.split(' ')

        # 3. Get or create a Django user and log them in
        user, created = User.objects.get_or_create(
            username=email or username,
            defaults={
                'email': email or '',
                'first_name': name[0] if name else '',
                'last_name': ' '.join(name[1:]) if len(name) > 1 else ''
            }
        )
        
        if created:
            user.set_unusable_password()
            user.save()

        # Store in Firestore
        from firebase_admin import firestore
        db = firestore.client()
        user_doc = db.collection('users').document(user.username)
        user_doc.set({
            'email': email or '',
            'name': name_str,
            'username': username,
            'provider': 'github',
            'registered_at': firestore.SERVER_TIMESTAMP
        }, merge=True)

        login(request, user)

    except requests.RequestException as e:
        logging.error(f"GitHub callback error: {e}")
        return redirect('login')

    return redirect('dashboard')

def register_view(request):
    """Handles user registration and sending OTP."""
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        password_conf = request.POST.get('password_conf')

        if password != password_conf:
            messages.error(request, "Passwords do not match.")
            return render(request, 'main/register.html')

        # Check if user already exists in Firebase
        try:
            existing_user = auth.get_user_by_email(email)
            messages.error(request, "An account with this email already exists.")
            return render(request, 'main/register.html')
        except auth.UserNotFoundError:
            pass  # Good, user doesn't exist

        otp = str(random.randint(100000, 999999))
        request.session['registration_data'] = {
            'email': email,
            'password': password,  # Store plain password temporarily for Firebase
            'otp': otp,
            'otp_expiry': time.time() + 300,  # 5-minute expiry
        }

        send_mail(
            'Your Graphify Verification Code',
            f'Welcome to Graphify! Your one-time password is: {otp}',
            'noreply@graphify.com',
            [email],
            fail_silently=False,
        )
        messages.success(request, f"A verification code has been sent to {email}.")
        return redirect('verify_otp')

    return render(request, 'main/register.html')

def otp_verify_view(request):
    """Verifies the OTP and creates the user account in Firebase."""
    reg_data = request.session.get('registration_data')
    if not reg_data:
        messages.error(request, "Session expired. Please try registering again.")
        return redirect('register')

    if request.method == 'POST':
        submitted_otp = request.POST.get('otp')
        if time.time() > reg_data.get('otp_expiry', 0):
            messages.error(request, "OTP has expired. Please register again.")
            del request.session['registration_data']
            return redirect('register')

        if submitted_otp == reg_data.get('otp'):
            try:
                # Create user in Firebase Auth
                firebase_user = auth.create_user(
                    email=reg_data['email'],
                    password=reg_data['password']
                )
                
                # Store additional data in Firestore
                from firebase_admin import firestore
                db = firestore.client()
                user_doc = db.collection('users').document(firebase_user.uid)
                user_doc.set({
                    'email': reg_data['email'],
                    'firebase_uid': firebase_user.uid,
                    'registered_at': firestore.SERVER_TIMESTAMP,
                    'provider': 'email'
                })
                
                # Create a minimal Django user for session management
                django_user, created = User.objects.get_or_create(
                    username=reg_data['email'],
                    defaults={
                        'email': reg_data['email'],
                        'first_name': '',
                        'last_name': ''
                    }
                )
                if created:
                    django_user.set_password(reg_data['password'])  # Set password for Django auth
                    django_user.save()
                
                del request.session['registration_data']
                login(request, django_user)
                return redirect('dashboard')
            except Exception as e:
                logging.error(f"Firebase user creation error: {e}")
                messages.error(request, "Registration failed. Please try again.")
                return redirect('register')
        else:
            messages.error(request, "Invalid OTP. Please try again.")

    return render(request, 'main/verify_otp.html', {'email': reg_data.get('email')})