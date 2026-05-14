path = r'd:\Detection-of-Phishing-Website-Using-Machine-Learning-master\Project_Webapp\django Integration\django Integration\django_admin\api\views.py'
with open(path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Replace @permission_classes([IsAuthenticated]) with empty permissions on lines 398 and 461 (1-indexed)
count = 0
for i, line in enumerate(lines):
    if '@permission_classes([IsAuthenticated])' in line:
        lines[i] = line.replace('@permission_classes([IsAuthenticated])', '@permission_classes([])')
        count += 1

with open(path, 'w', encoding='utf-8') as f:
    f.writelines(lines)

print(f"Replaced {count} lines")
