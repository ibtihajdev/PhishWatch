with open(r'd:\Detection-of-Phishing-Website-Using-Machine-Learning-master\Project_Webapp\phisbusterv2\index.html', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace(
    "      : 'https://phishwatch-api.onrender.com';",
    "      : 'https://phishwatch-production.up.railway.app';"
)

with open(r'd:\Detection-of-Phishing-Website-Using-Machine-Learning-master\Project_Webapp\phisbusterv2\index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print("done")
