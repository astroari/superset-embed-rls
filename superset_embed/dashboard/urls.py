from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard_view, name='dashboard'),
    path('api/guest-token/', views.get_guest_token, name='get_guest_token'),
]
