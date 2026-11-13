# Fix the esc function - write exact bytes
with open('web/app.js', 'r', encoding='utf-8') as f:
    content = f.read()

# The correct line with literal HTML entity strings (no actual quote chars in the values)
# & < > " '
# These are just text strings, not actual HTML entities being rendered
new_line = "const esc=x=>String(x??'').replace(/[&<>\\\"/']/g,c=>({'&':'&','<':'<','>':'>','\"':'"',\"'\":'''}[c]));\n"

# Replace the esc line
import re
content = re.sub(r'const esc=.*?;\n', new_line, content)

with open('web/app.js', 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed!")
print(repr(new_line))