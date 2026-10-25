with open('C:/Users/smecy/Downloads/WireSploit-v4.0.1-Patched/WireSploit-v4.0.1/web/app.js', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix the typo
content = content.replace('async function repairToolool', 'async function repairTool')

with open('C:/Users/smecy/Downloads/WireSploit-v4.0.1-Patched/WireSploit-v4.0.1/web/app.js', 'w', encoding='utf-8') as f:
    f.write(content)

print('Fixed typo')