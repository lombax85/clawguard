import forge from 'node-forge';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import net from 'net';

export interface CertPair {
  cert: string; // PEM
  key: string;  // PEM
}

export class CertManager {
  private caCert: forge.pki.Certificate;
  private caKey: forge.pki.rsa.PrivateKey;
  private cache: Map<string, CertPair> = new Map();
  private caDir: string;

  constructor(caDir: string) {
    this.caDir = caDir;
    fs.mkdirSync(caDir, { recursive: true });

    const caCertPath = path.join(caDir, 'ca.crt');
    const caKeyPath = path.join(caDir, 'ca.key');
    const tlsCertPath = path.join(caDir, 'tls.crt');
    const tlsKeyPath = path.join(caDir, 'tls.key');

    const certPath = fs.existsSync(tlsCertPath) ? tlsCertPath : caCertPath;
    const keyPath = fs.existsSync(tlsKeyPath) ? tlsKeyPath : caKeyPath;

    if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
      try {
        this.caCert = forge.pki.certificateFromPem(fs.readFileSync(certPath, 'utf-8'));
        this.caKey = forge.pki.privateKeyFromPem(fs.readFileSync(keyPath, 'utf-8'));
        console.log(`   ✓ CA loaded from ${certPath}`);
      } catch (err) {
        console.error(`❌ Failed to parse existing CA certificate from ${certPath}: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      }
    } else {
      const ca = this.generateCA();
      this.caCert = ca.cert;
      this.caKey = ca.key;
      fs.writeFileSync(caCertPath, forge.pki.certificateToPem(ca.cert));
      fs.writeFileSync(caKeyPath, forge.pki.privateKeyToPem(ca.key));
      console.log(`   ✓ CA generated and saved to ${caDir}`);
      console.log(`   ⚠ Trust this CA on the agent machine: ${caCertPath}`);
    }
  }

  getCaCertPath(): string {
    return path.join(this.caDir, 'ca.crt');
  }

  getCertForHost(hostname: string): CertPair {
    const cached = this.cache.get(hostname);
    if (cached) return cached;

    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();

    cert.publicKey = keys.publicKey;
    cert.serialNumber = Date.now().toString(16) + Math.floor(Math.random() * 1000).toString(16);

    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    cert.setSubject([{ name: 'commonName', value: hostname }]);
    cert.setIssuer(this.caCert.subject.attributes);

    cert.setExtensions([
      { name: 'subjectAltName', altNames: [{ type: 2, value: hostname }] },
      { name: 'basicConstraints', cA: false },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
      { name: 'extKeyUsage', serverAuth: true },
    ]);

    cert.sign(this.caKey, forge.md.sha256.create());

    const pair: CertPair = {
      cert: forge.pki.certificateToPem(cert),
      key: forge.pki.privateKeyToPem(keys.privateKey),
    };

    this.cache.set(hostname, pair);
    return pair;
  }

  /**
   * Issues a leaf cert covering the given DNS names + IPs as SAN entries.
   * Persists to disk under <caDir>/<name>.{crt,key}, with a sidecar
   * <caDir>/<name>.json fingerprint so we regenerate when the input set changes.
   * Used for the admin HTTPS listener (browser secure context for Web Push).
   */
  getServerCert(name: string, dnsNames: string[], ips: string[]): CertPair {
    const dedupedDns = [...new Set(dnsNames.filter(Boolean))].sort();
    const dedupedIps = [...new Set(ips.filter(Boolean))].sort();
    const fingerprint = crypto
      .createHash('sha256')
      .update(`${dedupedDns.join(',')}|${dedupedIps.join(',')}`)
      .digest('hex');

    const certPath = path.join(this.caDir, `${name}.crt`);
    const keyPath = path.join(this.caDir, `${name}.key`);
    const metaPath = path.join(this.caDir, `${name}.json`);

    if (fs.existsSync(certPath) && fs.existsSync(keyPath) && fs.existsSync(metaPath)) {
      try {
        const meta = JSON.parse(fs.readFileSync(metaPath, 'utf-8')) as { fingerprint?: string };
        if (meta.fingerprint === fingerprint) {
          const pair: CertPair = {
            cert: fs.readFileSync(certPath, 'utf-8'),
            key: fs.readFileSync(keyPath, 'utf-8'),
          };
          console.log(`   ✓ Loaded ${name} cert from ${certPath} (SAN: ${dedupedDns.length} DNS + ${dedupedIps.length} IP)`);
          return pair;
        }
        console.log(`   ↻ Regenerating ${name} cert — SAN list changed`);
      } catch {
        // Ignore parse errors and regenerate below
      }
    }

    // Build SAN list — primary CN must also be reflected in SAN per RFC 5280
    const allDns = new Set(dedupedDns);
    const allIps = new Set(dedupedIps);
    const cn = dedupedDns[0] || dedupedIps[0] || name;
    if (net.isIP(cn)) allIps.add(cn); else allDns.add(cn);

    // forge accepts SAN entries as { type: 2, value } for DNS and { type: 7, ip } for IP.
    // The @types definitions don't expose this shape cleanly, so we keep it untyped.
    const altNames: Array<{ type: number; value?: string; ip?: string }> = [];
    for (const dns of allDns) altNames.push({ type: 2, value: dns });
    for (const ip of allIps) altNames.push({ type: 7, ip });

    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = Date.now().toString(16) + Math.floor(Math.random() * 1000).toString(16);
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
    cert.setSubject([{ name: 'commonName', value: cn }]);
    cert.setIssuer(this.caCert.subject.attributes);
    cert.setExtensions([
      { name: 'subjectAltName', altNames },
      { name: 'basicConstraints', cA: false },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
      { name: 'extKeyUsage', serverAuth: true },
    ]);
    cert.sign(this.caKey, forge.md.sha256.create());

    const pair: CertPair = {
      cert: forge.pki.certificateToPem(cert),
      key: forge.pki.privateKeyToPem(keys.privateKey),
    };

    fs.writeFileSync(certPath, pair.cert);
    fs.writeFileSync(keyPath, pair.key, { mode: 0o600 });
    fs.writeFileSync(metaPath, JSON.stringify({ fingerprint, dnsNames: dedupedDns, ips: dedupedIps }, null, 2));
    console.log(`   ✓ Issued ${name} cert (CN=${cn}, ${allDns.size} DNS SAN + ${allIps.size} IP SAN)`);
    return pair;
  }

  private generateCA(): { cert: forge.pki.Certificate; key: forge.pki.rsa.PrivateKey } {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();

    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';

    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

    const attrs = [
      { name: 'commonName', value: 'ClawGuard MITM CA' },
      { name: 'organizationName', value: 'ClawGuard' },
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);

    cert.setExtensions([
      { name: 'basicConstraints', cA: true },
      { name: 'keyUsage', keyCertSign: true, cRLSign: true },
    ]);

    cert.sign(keys.privateKey, forge.md.sha256.create());
    return { cert, key: keys.privateKey };
  }
}
