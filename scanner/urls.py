from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('scan/', views.scan_form_view, name='scan_form'),
    path('scan-result/<int:scan_id>/', views.scan_result_view, name='scan_result'),
    path('scan-history/', views.scan_history_view, name='scan_history'),
]
