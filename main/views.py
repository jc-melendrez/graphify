import json
import logging
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from firebase_admin import auth
from django.contrib.auth.models import User
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required

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