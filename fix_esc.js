const fs = require('fs');

const content = fs.readFileSync('web/app.js', 'utf8');

// Direct string construction - using escape codes for the HTML entities
// & = &\#38; but we write it as literal string "&"
const newLine = 'const esc=x=>String(x??\'').replace(/[&<>"\']/g,c=>({\'&\':\'&\',\'<\':\'<\',\'>\':\'>\',\'"\':\'"\',\'"\':\'"\'}(c]));';

const newContent = content.replace(/const esc=.*?;/, newLine);

fs.writeFileSync('web/app.js', newContent);

console.log('Fixed!');
console.log(newLine);