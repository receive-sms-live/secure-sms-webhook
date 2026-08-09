import { createReadStream, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, normalize, sep } from 'node:path';

const root = join(process.cwd(), 'site');
const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml' };
const server = createServer((req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  const relative = pathname === '/' ? 'index.html' : pathname.slice(1);
  const path = normalize(join(root, relative));
  if (path !== root && !path.startsWith(`${root}${sep}`)) {
    res.writeHead(403).end('Forbidden');
    return;
  }
  try {
    if (!statSync(path).isFile()) throw new Error('Not a file');
    res.writeHead(200, { 'content-type': types[extname(path)] || 'application/octet-stream' });
    createReadStream(path).pipe(res);
  } catch {
    res.writeHead(404).end('Not found');
  }
});
server.listen(4173, '127.0.0.1', () => {
  console.log('Documentation site: http://127.0.0.1:4173');
});
