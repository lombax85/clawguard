const http = require('http');
const https = require('https');
const fs = require('fs');
const { URL } = require('url');

const tlsOptions = {
  cert: fs.readFileSync('/tls/tls.crt'),
  key: fs.readFileSync('/tls/tls.key'),
};

function handler(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const chunks = [];

  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', () => {
    const body = Buffer.concat(chunks).toString('utf-8');

    const echo = {
      method: req.method,
      path: url.pathname,
      query: Object.fromEntries(url.searchParams),
      headers: req.headers,
    };

    if (body) {
      try {
        echo.body = JSON.parse(body);
      } catch {
        echo.body = body;
      }
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(echo, null, 2));
  });
}

https.createServer(tlsOptions, handler).listen(3000, '0.0.0.0', () => {
  console.log('JSON Server HTTPS running on https://0.0.0.0:3000');
});

http.createServer(handler).listen(3080, '0.0.0.0', () => {
  console.log('JSON Server HTTP running on http://0.0.0.0:3080');
});
