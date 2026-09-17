import { evaluateScaDependencyRules } from '@/lib/rules/sca-dependency-rules';

const testPackageJson = `{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "license": "GPL-3.0",
  "dependencies": {
    "axios": "^0.21.1",
    "lodash": "^4.17.15",
    "jsonwebtoken": "^8.5.1",
    "request": "^2.88.2"
  },
  "devDependencies": {
    "express": "4.18.1"
  }
}`;

const lines = testPackageJson.split('\n');
const counter = { count: 1 };
const result = evaluateScaDependencyRules(
  { path: 'package.json', content: testPackageJson },
  lines,
  testPackageJson,
  counter
);

console.log(`Total SCA findings detected: ${result.findings.length}`);
result.findings.forEach((f, i) => {
  console.log(`\n[${i + 1}] [${f.severity}] [${f.category}] ${f.title}`);
  console.log(`    Line: ${f.lineRange} | Snippet: ${f.snippet}`);
  if (f.diffPatch) {
    console.log(`    Diff Patch:\n${f.diffPatch}`);
  }
});

if (result.findings.length < 5) {
  throw new Error(`Expected at least 5 findings, got ${result.findings.length}`);
}
console.log('\n✅ All SCA test assertions passed successfully!');
