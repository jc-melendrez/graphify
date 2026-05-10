from django.shortcuts import render
from django.contrib.auth.decorators import login_required

@login_required
def dashboard_view(request):
    """Displays the main dashboard for logged-in users."""
    return render(request, 'main/dashboard.html')