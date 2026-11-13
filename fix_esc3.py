import base64

# The correct line 4, base64 encoded
# const esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&','<':'<','>':'>','"':""","'":'''}[c]));
correct_b64 = "Y29uc3QgZXNjPXg9PlN0cmluZyh4Pz8nJykucmVwbGFjZSgvWzY8PiIiJ10vZyxlPT4oeydgJic6JCYmYW1wOycscydcJzocJmx0OycsJz4nOicmZ3Q7JywiXCIiOiImcXVvdDsiLCIiJyI6IiYjMzk7In1bY10pKTs="

correct_line = base64.b64decode(correct_b64).decode('utf-8') + "\n"

with open('web/app.js', 'r', encoding='utf-8') as f:
    content = f.read()

import re
content = re.sub(r'const esc=.*?;\n', correct_line, content)

with open('web/app.js', 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed!")
print(repr(correct_line))