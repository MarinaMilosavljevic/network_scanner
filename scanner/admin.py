from django.contrib import admin
from .models import ScanResult

@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ('target', 'user', 'scanned_at')
    search_fields = ('target', 'user__username')
    list_filter = ('scanned_at',)
