with open('C:/Users/smecy/Downloads/WireSploit-v4.0.1-Patched/WireSploit-v4.0.1/web/app.js', 'r', encoding='utf-8') as f:
    content = f.read()

# Find the boundary
search = '}).join'
idx = content.find(search)
if idx > 0:
    print('Found at:', idx)
    print(repr(content[idx:idx+200]))
else:
    print('Not found')