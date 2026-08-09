import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { extname, join } from 'node:path';

const roots = ['src', 'cli', 'scripts', 'tests', 'examples'];
const files = [];
function collect(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) collect(path);
    else if (extname(entry.name) === '.js') files.push(path);
  }
}
for (const root of roots) collect(root);

for (const file of files) {
  const checked = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (checked.status !== 0) {
    process.stderr.write(checked.stderr);
    process.exit(checked.status || 1);
  }
}
console.log(`Syntax check passed for ${files.length} JavaScript files.`);
