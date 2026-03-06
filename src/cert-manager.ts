import forge from 'node-forge';
import fs from 'fs';
import path from 'path';

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

    if (fs.existsSync(caCertPath) && fs.existsSync(caKeyPath)) {
      this.caCert = forge.pki.certificateFromPem(fs.readFileSync(caCertPath, 'utf-8'));
      this.caKey = forge.pki.privateKeyFromPem(fs.readFileSync(caKeyPath, 'utf-8'));
      console.log(`   ✓ CA loaded from ${caDir}`);
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
