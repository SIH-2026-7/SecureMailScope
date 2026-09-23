import {spawn} from 'node:child_process';
import {existsSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const python = path.join(root, 'backend', '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
if (!existsSync(python)) {
  console.error('Backend environment missing. Follow the Python setup in README.md.');
  process.exit(1);
}
const child = spawn(python, ['-m', 'uvicorn', 'app.main:app', '--app-dir', path.join(root, 'backend'), '--host', '127.0.0.1', '--port', '8000'], {stdio: 'inherit', windowsHide: true});
child.on('exit', code => process.exit(code ?? 0));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
