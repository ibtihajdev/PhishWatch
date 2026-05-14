from django.contrib import admin
from .models import FalsePositiveReport, ScanHistory

@admin.register(FalsePositiveReport)
class FalsePositiveReportAdmin(admin.ModelAdmin):
    list_display = ('url', 'reported_at', 'reviewed', 'correct_label')
    list_filter = ('reviewed', 'correct_label')
    search_fields = ('url',)

@admin.register(ScanHistory)
class ScanHistoryAdmin(admin.ModelAdmin):
    list_display = ('url', 'user', 'verdict', 'confidence', 'timestamp')
    list_filter = ('verdict', 'timestamp')
    search_fields = ('url', 'user__email')
