from django.shortcuts import render
from django.contrib.auth.decorators import login_required

@login_required
def dashie(request):
    """Displays the main dashboard for logged-in users."""
    return render(request, 'main/dashie.html')

def landing_page(request):
    
    return render(request, 'main/landing_page.html')