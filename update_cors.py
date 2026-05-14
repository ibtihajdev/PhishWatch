settings_path = r'd:\Detection-of-Phishing-Website-Using-Machine-Learning-master\Project_Webapp\django Integration\django Integration\django_admin\django_admin\settings.py'

with open(settings_path, 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace(
    'https://your-app-name.netlify.app',
    'https://phishwatchwebapp.netlify.app'
)

with open(settings_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("done")
