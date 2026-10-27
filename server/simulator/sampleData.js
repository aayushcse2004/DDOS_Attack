/**
 * Realistic safe sample data for in-memory network traffic simulation.
 * Uses strictly private RFC-1918 and documentation IP addresses.
 */

const BENIGN_IPS = [
  '192.168.1.10',
  '192.168.1.11',
  '192.168.1.12',
  '192.168.1.15',
  '192.168.1.22',
  '192.168.1.35',
  '10.0.0.5',
  '10.0.0.8',
  '10.0.0.14',
  '10.0.0.21',
  '172.16.0.12',
  '172.16.0.19'
];

const ATTACK_IPS = [
  '192.168.1.101',
  '192.168.1.102',
  '192.168.1.103',
  '192.168.1.104',
  '192.168.1.105',
  '10.0.4.15',
  '10.0.4.18',
  '10.0.4.22',
  '172.16.9.50',
  '172.16.9.51'
];

const TARGET_SERVER = {
  ip: '192.168.1.1',
  hostname: 'enterprise-core-gateway',
  services: [
    { port: 80, name: 'HTTP Web Service' },
    { port: 443, name: 'HTTPS Secure Gateway' },
    { port: 53, name: 'Internal DNS Resolver' },
    { port: 8080, name: 'Internal REST API' }
  ]
};

const HTTP_PATHS = [
  '/index.html',
  '/api/v1/auth/login',
  '/api/v1/dashboard/metrics',
  '/static/css/main.css',
  '/api/v1/user/profile',
  '/checkout/process',
  '/search?q=cybersecurity'
];

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0',
  'CyberBot/2.4 (Simulated-Scraper-Tool)',
  'CustomPythonRequests/2.31'
];

module.exports = {
  BENIGN_IPS,
  ATTACK_IPS,
  TARGET_SERVER,
  HTTP_PATHS,
  USER_AGENTS
};
