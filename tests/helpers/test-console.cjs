const { Console } = require('node:console');

// Node 22 mixes test events and console stdout in one IPC stream. Unicode logs
// can corrupt that stream (nodejs/node#64061, fixed upstream by #64706).
// Keep every console message visible on stderr, separate from test results.
global.console = new Console({ stdout: process.stderr, stderr: process.stderr });
