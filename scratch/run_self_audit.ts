import fs from 'fs';
import path from 'path';
import { runStaticCodeScan, CodeFile } from '../lib/scanner-engine';

const repoRoot = path.resolve(__dirname, '..');

function getFiles(dir: string, fileList: CodeFile[] = []): CodeFile[] {
  const items = fs.readdirSync(dir);
  for (const item of items) {
    if (['node_modules', '.next', '.git', 'scratch', 'dist', 'build', '.agent'].includes(item)) continue;
    const fullPath = path.join(dir, item);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      getFiles(fullPath, fileList);
    } else if (/\.(tsx|ts|jsx|js|html|css|sql|json|yml|yaml|dockerfile)$/i.test(item)) {
      const relPath = path.relative(repoRoot, fullPath).replace(/\\/g, '/');
      try {
        const content = fs.readFileSync(fullPath, 'utf-8');
        fileList.push({ path: relPath, content });
      } catch (e) {
        // Skip unreadable
      }
    }
  }
  return fileList;
}

async function main() {
  const files = getFiles(repoRoot);
  console.log(`Auditing ${files.length} project files...`);

  const result = await runStaticCodeScan(files, 'shipguard-saas (main)');
  console.log('\n================ AUDIT SUMMARY ================');
  console.log(`Readiness Score: ${result.score}/100`);
  console.log(`Gate Status:     ${result.gateStatus}`);
  console.log(`Critical Count:  ${result.criticalCount}`);
  console.log(`High Count:      ${result.highCount}`);
  console.log(`Medium Count:    ${result.mediumCount}`);
  console.log(`Low Count:       ${result.lowCount}`);
  console.log(`Total Findings:  ${result.findings.length}`);
  console.log('================================================\n');

  if (result.findings.length > 0) {
    console.log('Findings list:');
    result.findings.forEach((f, idx) => {
      console.log(`${idx + 1}. [${f.severity}] ${f.title} (${f.filePath}:${f.lineRange})`);
    });
  } else {
    console.log('🎉 ZERO FINDINGS! PERFECT 100/100 DEPLOYMENT READINESS!');
  }
}

main().catch(console.error);
