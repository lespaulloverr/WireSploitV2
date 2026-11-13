# Fix the esc function - construct strings programmatically to avoid HTML entity interpretation

with open('web/app.js', 'r', encoding='utf-8') as f:
    content = f.read()

# Build the correct entity strings programmatically
amp = '&' + 'amp;'
lt = '&' + 'lt;'
gt = '&' + 'gt;'
quot = '&' + 'quot;'
hash39 = '&' + '#39;'

# The correct line - escape braces for format()
# Note: the regex is /[&<>"']/g and the replacement is c=>({...}[c])
new_line = "const esc=x=>String(x??'').replace(/[&<>\\\"/']/g,c=>({{'&':'{amp}','<':'{lt}','>':'{gt}','\"':'{quot}',\"'\":'{hash39}'}}[c]));\n".format(
    amp=amp, lt=lt, gt=gt, quot=quot, hash39=hash39
)

# Replace the esc line
import re
content = re.sub(r'const esc=.*?;\n', new_line, content)

with open('web/app.js', 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed!")
print(repr(new_line))