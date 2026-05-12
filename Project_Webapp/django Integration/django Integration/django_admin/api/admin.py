from django.contrib import admin
from .models import FalsePositiveReport

@admin.register(FalsePositiveReport)
class FalsePositiveReportAdmin(admin.ModelAdmin):
    list_display = ('url', 'reported_at', 'reviewed', 'correct_label')
    list_filter = ('reviewed', 'correct_label')
    search_fields = ('url',)
