import { Hono } from 'hono';

type Env = {
  ADMIN_API_KEY: string;
  ADMIN_IP_ALLOWLIST: string; // comma-separated IPv4 list, e.g. "142.90.207.149"
};

const app = new Hono<{ Bindings: Env }>();

// Request ID and Logging Middleware
app.use('*', async (c, next) => {
  const start = Date.now();
  let reqId = c.req.header('x-request-id');

  if (!reqId) {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
      reqId = crypto.randomUUID();
    } else {
      reqId = `${Date.now()}-${Math.random()}`;
    }
  }

  c.header('x-request-id', reqId);

  try {
    await next();
  } finally {
    const ms = Date.now() - start;
    const ip = c.req.header('CF-Connecting-IP') || 'unknown';
    const ua = c.req.header('User-Agent') || 'unknown';

    // Construct the log object EXACTLY as required
    const logData = {
      at: new Date().toISOString(),
      req_id: reqId,
      method: c.req.method,
      path: new URL(c.req.url).pathname,
      status: c.res.status,
      ms: ms,
      ip: ip,
      ua: ua
    };

    console.log(JSON.stringify(logData));
  }
});

// Admin Protection Middleware
app.use('/admin/*', async (c, next) => {
  // A) IP allowlist check
  const ip = c.req.header('CF-Connecting-IP');
  const allowlistStr = c.env.ADMIN_IP_ALLOWLIST || '';
  const allowlist = allowlistStr.split(',').map(s => s.trim()).filter(s => s !== '');

  if (!ip || !allowlist.includes(ip)) {
    return c.json({ ok: false, error: 'forbidden' }, 403);
  }

  // B) API key check
  const authHeader = c.req.header('Authorization');
  const expectedKey = c.env.ADMIN_API_KEY;

  if (!expectedKey || authHeader !== `Bearer ${expectedKey}`) {
    return c.json({ ok: false, error: 'unauthorized' }, 401);
  }

  await next();
});

// Route 1: GET /health (PUBLIC)
app.get('/health', (c) => {
  return c.json({
    ok: true,
    service: 'bus-auth',
    version: '0.1.0'
  });
});

// Route 2: GET /admin/health/detailed (ADMIN, READ-ONLY)
app.get('/admin/health/detailed', (c) => {
  const ip = c.req.header('CF-Connecting-IP') || 'unknown';
  const hasAdminKey = !!(c.env.ADMIN_API_KEY && c.env.ADMIN_API_KEY.length > 0);

  return c.json({
    ok: true,
    admin: true,
    ip: ip,
    has_admin_key: hasAdminKey,
    allowlist: c.env.ADMIN_IP_ALLOWLIST,
    version: '0.1.0'
  });
});

export default app;
