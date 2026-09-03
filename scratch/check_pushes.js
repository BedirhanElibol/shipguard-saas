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
const allPushes = [];

files.forEach(f => {
  const content = fs.readFileSync(f, 'utf8');
  const regex = /router\.push\(([^)]+)\)/g;
  let match;
  while ((match = regex.exec(content)) !== null) {
    allPushes.push({ file: f, target: match[1] });
  }
});

console.log(JSON.stringify(allPushes, null, 2));
