import {useEffect, useState} from 'react';
import {useAxios} from '../../hooks/useAxios';
import {useAuth} from '../../hooks/useAuth';
import {setAdminVerification} from '../../utils/adminVerification';
import './admin-security.css';

export default function AdminSecurityGate({children}) {
  const api = useAxios();
  const {user, logout} = useAuth();
  const [status, setStatus] = useState(null);
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [sent, setSent] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let active = true;
    api.get('/api/auth/admin-mfa/status').then(response => {if(active)setStatus(response.data);}).catch(() => {if(active)setError('Unable to check administrator security. Retry before continuing.');});
    const verify = event => {setStatus(previous=>({...previous,verified:false}));setError(event.detail);setCode('');setPassword('');setSent(false);setMessage('');};
    window.addEventListener('admin-verification-required', verify);
    return () => {active=false;window.removeEventListener('admin-verification-required',verify);};
  }, [api]);
  async function sendCode() {
    const response = await api.post('/api/auth/admin-mfa/send-code', {password});
    setSent(true); setCode(''); setMessage(response.data.message);
  }
  async function submit(event) {
    event.preventDefault(); setError('');setBusy(true);
    try {
      if (!sent) {await sendCode();return;}
      const response = await api.post('/api/auth/admin-mfa/verify',{password,code:code.trim()});
      setAdminVerification(user.id,response.data.verificationToken);
      setPassword('');setCode('');setSent(false);setMessage('');
      setStatus({...status,enrolled:true,verified:true});
    } catch(error) {setError(error.response?.data?.message || 'Verification failed. Check your code and try again.');}
    finally {setBusy(false);}
  }
  if(status && (!status.required || status.verified))return children;
  return <main className="admin-security-shell"><section className="admin-security-panel" aria-labelledby="admin-security-title">
    <h1 id="admin-security-title">Verify your administrator email</h1>
    {error && <p className="admin-security-error" role="alert">{error}</p>}
    {message && <p role="status">{message}</p>}
    {!status ? <><p role="status">Checking account security…</p>{error && <button onClick={()=>window.location.reload()}>Retry</button>}</> : <form onSubmit={submit} aria-busy={busy}>
      <p>{sent ? `Enter the six-digit code sent to ${user.email}. The code expires in five minutes.` : `Send a verification code to ${user.email} to continue.`}</p>
      <label htmlFor="admin-security-password">Current password</label>
      <input id="admin-security-password" type="password" autoComplete="current-password" value={password} onChange={event=>setPassword(event.target.value)} required maxLength={72} disabled={busy}/>
      {sent && <><label htmlFor="admin-security-code">Email verification code</label>
        <input id="admin-security-code" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" value={code} onChange={event=>setCode(event.target.value)} required minLength={6} maxLength={6} disabled={busy}/></>}
      <button type="submit" disabled={busy}>{busy ? 'Please wait…' : sent ? 'Verify and continue' : 'Send email code'}</button>
      {sent && <button type="button" className="admin-security-secondary" disabled={busy || !password} onClick={async()=>{setBusy(true);setError('');setMessage('');try{await sendCode();}catch(error){setError(error.response?.data?.message || 'Unable to resend code. Try again.');}finally{setBusy(false);}}}>Resend code</button>}
    </form>}
    <button type="button" className="admin-security-secondary" onClick={logout}>Sign out</button>
  </section></main>;
}
