// api/ssl-check.js (สำหรับ Vercel)
const https = require('https');
const { URL } = require('url');

export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    const domain = req.query.domain || req.body?.domain;
    
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain parameter is required'
      });
    }

    // Clean domain (remove protocol and www)
    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/^www\./, '');
    
    const certInfo = await getSSLCertificate(cleanDomain);
    
    if (certInfo.error) {
      return res.status(400).json({
        success: false,
        error: certInfo.error
      });
    }

    return res.status(200).json({
      success: true,
      ...certInfo
    });

  } catch (error) {
    console.error('SSL Check Error:', error);
    return res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
}

function getSSLCertificate(domain) {
  return new Promise((resolve) => {
    const options = {
      hostname: domain,
      port: 443,
      method: 'GET',
      timeout: 10000,
      rejectUnauthorized: false // Allow self-signed certificates
    };

    const request = https.request(options, (response) => {
      const cert = response.connection.getPeerCertificate();
      
      if (!cert || Object.keys(cert).length === 0) {
        resolve({
          error: 'No SSL certificate found'
        });
        return;
      }

      try {
        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const now = new Date();
        const daysLeft = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));

        // Extract DNS names
        const dnsNames = [];
        if (cert.subject && cert.subject.CN) {
          dnsNames.push(cert.subject.CN);
        }
        if (cert.subjectaltname) {
          const altNames = cert.subjectaltname
            .split(', ')
            .filter(name => name.startsWith('DNS:'))
            .map(name => name.substring(4));
          dnsNames.push(...altNames);
        }

        resolve({
          subject: cert.subject?.CN || domain,
          issuer: {
            name: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
            friendly_name: cert.issuer?.O || cert.issuer?.CN || 'Unknown'
          },
          valid_from: validFrom.toISOString(),
          valid_to: validTo.toISOString(),
          days_left: daysLeft,
          serial_number: cert.serialNumber || 'Unknown',
          fingerprint: cert.fingerprint || 'Unknown',
          dns_names: [...new Set(dnsNames)], // Remove duplicates
          revoked: false // Note: Checking revocation requires additional API calls
        });
      } catch (parseError) {
        resolve({
          error: 'Failed to parse certificate data'
        });
      }
    });

    request.on('error', (error) => {
      console.error('Request error:', error);
      resolve({
        error: `Connection failed: ${error.message}`
      });
    });

    request.on('timeout', () => {
      request.destroy();
      resolve({
        error: 'Connection timeout'
      });
    });

    request.setTimeout(10000);
    request.end();
  });
}