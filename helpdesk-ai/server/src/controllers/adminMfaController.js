const crypto = require('crypto');
const prisma = require('../prisma');
const { comparePassword } = require('../utils/password');
const mfa = require('../services/adminMfa');
async function password(req) {
  const user = await prisma.user.findUnique({ where: { id: req.user.id } });
  if (!user?.isActive || user.role !== 'ADMIN' || !(await comparePassword(String(req.body.password || ''), user.passwordHash))) {
    const error = new Error('Verification failed'); error.status = 403; error.publicMessage = 'Administrator verification failed.'; throw error;
  }
  return user;
}
async function status(req, res, next) {
  try {
    const [record] = await prisma.$queryRaw`SELECT "secret" FROM "AdminSecurity" WHERE "userId"=${req.user.id}`;
    const proof = record?.secret?.startsWith('email:') && mfa.verifyProof(req.headers['x-admin-verification'], req.user, record.secret);
    res.json({ method: 'email', required: mfa.required(), enrolled: !!record?.secret, verified: !!proof, recent: !!proof && Date.now() - proof.verifiedAt <= 5 * 60000 });
  } catch (error) { next(error); }
}
async function enroll(req, res, next) {
  try {
    const user = await password(req);
    const result = await prisma.$transaction(async tx => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`mfa:${user.id}`}))`;
      const [record] = await tx.$queryRaw`SELECT * FROM "AdminSecurity" WHERE "userId"=${user.id} FOR UPDATE`;
      if (record?.pendingExpiresAt && record.pendingExpiresAt.getTime() - 240000 > Date.now()) return false;
      const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
      const challenge = mfa.seal(JSON.stringify({ digest: mfa.hash(code), attempts: 0, version: user.tokenVersion || 0 }), `email-mfa:${user.id}`);
      await tx.$executeRaw`INSERT INTO "AdminSecurity" ("userId","pendingSecret","pendingExpiresAt") VALUES (${user.id},${challenge},${new Date(Date.now()+300000)}) ON CONFLICT ("userId") DO UPDATE SET "pendingSecret"=EXCLUDED."pendingSecret","pendingExpiresAt"=EXCLUDED."pendingExpiresAt"`;
      await require('../services/adminEmail').sendCode(user.email, code);
      return true;
    }, { timeout: 20000 });
    if (!result) return res.status(429).json({ message: 'Wait one minute before requesting another code.' });
    res.json({ message: 'Verification code sent to your administrator email.', expiresIn: 300 });
  } catch (error) { next(error); }
}
async function verify(req, res, next) {
  try {
    const user = await password(req);
    const result = await prisma.$transaction(async tx => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`mfa:${user.id}`}))`;
      const [record] = await tx.$queryRaw`SELECT * FROM "AdminSecurity" WHERE "userId"=${user.id} FOR UPDATE`;
      if (!record?.pendingSecret || !record.pendingExpiresAt || record.pendingExpiresAt <= new Date()) return null;
      let challenge;
      try { challenge = JSON.parse(mfa.open(record.pendingSecret, `email-mfa:${user.id}`)); } catch { return null; }
      if (challenge.attempts >= 5 || challenge.version !== (user.tokenVersion || 0)) return null;
      if (!crypto.timingSafeEqual(Buffer.from(challenge.digest), Buffer.from(mfa.hash(String(req.body.code))))) {
        challenge.attempts += 1;
        const pending = mfa.seal(JSON.stringify(challenge), `email-mfa:${user.id}`);
        await tx.$executeRaw`UPDATE "AdminSecurity" SET "pendingSecret"=${pending} WHERE "userId"=${user.id}`;
        return null;
      }
      const secret = 'email:' + crypto.randomBytes(32).toString('hex');
      await tx.$executeRaw`UPDATE "AdminSecurity" SET "secret"=${secret},"pendingSecret"=NULL,"pendingExpiresAt"=NULL,"lastCounter"=-1,"recoveryHashes"='[]'::jsonb WHERE "userId"=${user.id}`;
      return { verificationToken: mfa.issueProof(user, secret) };
    });
    if (!result) return res.status(400).json({ message: 'Code is invalid, expired, or has too many attempts. Request a new email code.' });
    res.json(result);
  } catch (error) { next(error); }
}
module.exports = { status, enroll, verify };
