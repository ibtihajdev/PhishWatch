import csv
from django.core.management.base import BaseCommand
from api.models import FalsePositiveReport

class Command(BaseCommand):
    help = 'Exports reviewed false positives to CSV for model retraining'

    def handle(self, *args, **kwargs):
        # Only export data that has been reviewed and labeled by a human
        reports = FalsePositiveReport.objects.filter(reviewed=True).exclude(correct_label__isnull=True)
        
        with open('retraining_data.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['url', 'label'])
            for report in reports:
                writer.writerow([report.url, report.correct_label])
                
        self.stdout.write(self.style.SUCCESS(f'Successfully exported {reports.count()} reports.'))
