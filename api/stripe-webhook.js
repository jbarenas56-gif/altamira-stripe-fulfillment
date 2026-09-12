const crypto = require('crypto');

function verifyStripeSignature(rawBody, signatureHeader, secret) {
  if (!signatureHeader || !secret) return false;

  const parts = signatureHeader.split(',');
  let timestamp = null;
  const signatures = [];

  for (const part of parts) {
    const [key, value] = part.split('=');
    if (key === 't') timestamp = value;
    if (key === 'v1') signatures.push(value);
  }

  if (!timestamp || signatures.length === 0) return false;

  const age = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
  if (!Number.isFinite(age) || age > 300) return false;

  const payload = `${timestamp}.${rawBody}`;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(payload, 'utf8')
    .digest('hex');

  return signatures.some((sig) => {
    try {
      const a = Buffer.from(sig, 'hex');
      const b = Buffer.from(expected, 'hex');
      return a.length === b.length && crypto.timingSafeEqual(a, b);
    } catch {
      return false;
    }
  });
}

async function readRawBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}

module.exports = async function handler(req, res) {
  if (req.method === 'GET') {
    return res.status(200).json({ ok: true, service: 'altamira-stripe-fulfillment' });
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).send('Method Not Allowed');
  }

  const {
    STRIPE_WEBHOOK_SECRET,
    RESEND_API_KEY,
    EMAIL_FROM,
    PAYMENT_LINK_ID,
    DOWNLOAD_URL,
  } = process.env;

  if (!STRIPE_WEBHOOK_SECRET || !RESEND_API_KEY || !EMAIL_FROM || !PAYMENT_LINK_ID || !DOWNLOAD_URL) {
    return res.status(500).send('Missing environment variables');
  }

  const rawBody = await readRawBody(req);
  const signature = req.headers['stripe-signature'];

  if (!verifyStripeSignature(rawBody, signature, STRIPE_WEBHOOK_SECRET)) {
    return res.status(400).send('Invalid Stripe signature');
  }

  let event;
  try {
    event = JSON.parse(rawBody);
  } catch {
    return res.status(400).send('Invalid JSON');
  }

  const allowedEvents = new Set([
    'checkout.session.completed',
    'checkout.session.async_payment_succeeded',
  ]);

  if (!allowedEvents.has(event.type)) {
    return res.status(200).json({ received: true, ignored: true });
  }

  const session = event.data && event.data.object;
  if (!session) return res.status(400).send('Missing session');

  if (session.payment_status !== 'paid') {
    return res.status(200).json({ received: true, ignored: 'not_paid' });
  }

  if (session.payment_link !== PAYMENT_LINK_ID) {
    return res.status(200).json({ received: true, ignored: 'wrong_payment_link' });
  }

  if (session.amount_total !== 700 || session.currency !== 'usd') {
    return res.status(200).json({ received: true, ignored: 'wrong_amount_or_currency' });
  }

  const buyerEmail = session.customer_details?.email || session.customer_email;
  if (!buyerEmail) return res.status(400).send('Missing buyer email');

  const html = `<!doctype html>
<html>
  <body style="font-family:Arial,Helvetica,sans-serif;line-height:1.6;color:#111111;">
    <h2>Tu 5M Scalping System PRO está listo</h2>
    <p>Gracias por tu compra.</p>
    <p><a href="${DOWNLOAD_URL}" style="display:inline-block;padding:12px 18px;background:#111111;color:#ffffff;text-decoration:none;border-radius:6px;">Descargar PDF</a></p>
    <p>Este material es educativo y no constituye asesoría financiera ni garantiza resultados.</p>
    <p>Altamira Digital</p>
  </body>
</html>`;

  const text = `Tu 5M Scalping System PRO está listo.\n\nDescarga: ${DOWNLOAD_URL}\n\nMaterial educativo. No constituye asesoría financiera ni garantiza resultados.\n\nAltamira Digital`;

  const resendResponse = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json',
      'Idempotency-Key': `stripe-${session.id}`,
    },
    body: JSON.stringify({
      from: EMAIL_FROM,
      to: [buyerEmail],
      subject: 'Tu 5M Scalping System PRO está listo',
      html,
      text,
    }),
  });

  if (!resendResponse.ok) {
    const detail = await resendResponse.text();
    console.error('Resend error:', resendResponse.status, detail);
    return res.status(500).send('Email delivery failed');
  }

  return res.status(200).json({ received: true, fulfilled: true });
};
