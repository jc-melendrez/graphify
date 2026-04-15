from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from firebase_admin import auth
import json


def login_page(request):
    return render(request, 'main/index.html')

def dashboard_view(request):
    return render(request, 'main/dashboard.html')

@csrf_exempt
def google_login(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            id_token = data.get('id_token')

            decoded_token = auth.verify_id_token(id_token)

            uid = decoded_token['uid']
            email = decoded_token['email']
            name = decoded_token['name']
            picture = decoded_token['picture']

            return JsonResponse({
                "status": "success",
                "email": email,
                "name": name,
                "picture": picture
            })
        except Exception as e:
            return JsonResponse({
                "status": "error",
                "message": str(e)}, 
                status=401
            )
    return JsonResponse({"status": "error", "message": "Post only"}, status=405)
