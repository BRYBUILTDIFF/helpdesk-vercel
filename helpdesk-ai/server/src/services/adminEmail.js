function unavailable(message) {
  const error = new Error(message);
  error.status = 503;
  error.publicMessage = message;
  return error;
}
function mailbox(value) {
  return typeof value === 'string' && /^[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+$/.test(value) && !/[^\x21-\x7e]/.test(value);
}
async function sendCode(email, code) {
  const sender = String(process.env.ADMIN_EMAIL_FROM || '').trim();
  const apiKey = process.env.RESEND_API_KEY;
  if (!sender || /[\r\n]/.test(sender) || !apiKey) {
    throw unavailable('Administrator email delivery is not configured.');
  }
  if (!mailbox(email) || !/^\d{6}$/.test(code)) {
    throw unavailable('Administrator email delivery details are invalid.');
  }
  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST', signal: AbortSignal.timeout(10000),
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json', 'User-Agent': 'HelpDesk-AI/1.0' },
      body: JSON.stringify({
        from: sender, to: [email],
        subject: 'Your HelpDesk AI administrator verification code',
        text: `Your HelpDesk AI administrator verification code is ${code}. It expires in 5 minutes and can be used once. If you did not request this code, change your account password.`
      })
    });
    if (!response.ok) throw new Error('Email provider rejected delivery');
  } catch {
    // Do not expose provider responses, authorization credentials, or verification codes.
    throw unavailable('Unable to send verification email. Try again later.');
  }
}
module.exports = { sendCode };
