with open('C:/Users/smecy/Downloads/WireSploit-v4.0.1-Patched/WireSploit-v4.0.1/web/app.js', 'r', encoding='utf-8') as f:
    content = f.read()

# Find all occurrences
search = '}).join'
idx = -1
for i in range(5):
    idx = content.find(search, idx + 1)
    if idx >= 0:
        print(f'Found {i} at:', idx)
        print(repr(content[idx:idx+150]))
    else:
        print(f'Not found {i}')
        break