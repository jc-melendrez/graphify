import json
import logging
import requests
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from firebase_admin import auth
from django.contrib.auth.models import User
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.urls import reverse

def login_page(request):
    # If user is already authenticated, redirect them to the dashboard
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'main/index.html')

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
                'email': email,
                'email': email or '',
                'first_name': name[0] if name else '',
                'last_name': ' '.join(name[1:]) if len(name) > 1 else ''
            }
        )
        login(request, user)

    except requests.RequestException as e:
        logging.error(f"GitHub callback error: {e}")
        return redirect('login')

    return redirect('dashboard')