const fs = require('fs');
const path = require('path');

function walk(dir) {
  let results = [];
  const list = fs.readdirSync(dir);
  list.forEach(file => {
    if (file === 'node_modules' || file === '.next' || file === '.git') return;
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat && stat.isDirectory()) {
      results = results.concat(walk(fullPath));
    } else if (file.endsWith('.tsx') || file.endsWith('.ts')) {
      results.push(fullPath);
    }
  });
  return results;
}

const files = walk('.');
const allHrefs = [];

files.forEach(f => {
  const content = fs.readFileSync(f, 'utf8');
  const regex = /href=["']([^"']+)["']/g;
  let match;
  while ((match = regex.exec(content)) !== null) {
    allHrefs.push({ file: f, href: match[1] });
  }
});

console.log(JSON.stringify(allHrefs, null, 2));
