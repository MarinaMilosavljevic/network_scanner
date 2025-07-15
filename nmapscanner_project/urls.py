from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView

urlpatterns = [
    path('admin/', admin.site.urls),

    # Redirect sa prazne putanje na /scan/
    path('', RedirectView.as_view(url='/scan/', permanent=False)),

    # Uključi URL-ove iz tvoje aplikacije scanner
    path('', include('scanner.urls')),
]
