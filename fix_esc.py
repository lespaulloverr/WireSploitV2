# Fix the esc function in web/app.js

# The correct line 4 as a string - using the actual HTML entity strings
correct_line = 'const esc=x=>String(x??"").replace(/[&<>"'"']/g,c=>({"&":"&","<":"<",">":">","\"":"\"","'"'"':"'"'"'}(c]));\n'

# Read the file
with open('web/app.js', 'r', encoding='utf-8') as f:
    content = f.read()

# Find the esc line
idx = content.find('const esc=')
if idx >= 0:
    # Find end of line
    end = content.find('\n', idx)
    if end < 0:
        end = len(content)
    # Replace
    content = content[:idx] + correct_line + content[end:]
    print('Replaced at index', idx)
else:
    print('Could not find esc line')

with open('web/app.js', 'w', encoding='utf-8') as f:
    f.write(content)

print('Done')