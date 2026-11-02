import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Layout } from '@/components/Layout';
import { ModeToggle } from '@/components/ModeToggle';
import { useMode } from '@/lib/mode';
import { useLab } from '@/hooks/useLab';

type Account = { username: string; role: string; password_hash: string; method: string; salt_characters: number; legacy_hint: string | null };

function AccountManager({ profile }: { profile: string }) {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('operator');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    fetch(`/api/${profile}/admin/users`, { signal: controller.signal, cache: 'no-store' })
      .then(async response => { if (!response.ok) throw new Error('Could not load accounts.'); return response.json(); })
      .then(data => setAccounts(data.users))
      .catch(e => { if (!controller.signal.aborted) setError(e.message); });
    return () => controller.abort();
  }, [profile]);
  async function create(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setMessage(''); setError('');
    try {
      const response = await fetch(`/api/${profile}/admin/users`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({username, password, role}) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Account creation failed.');
      setPassword(''); setUsername('');
      setMessage(`Created ${data.username} in ${profile}. The password was hashed before storage.`);
      const refreshed = await fetch(`/api/${profile}/admin/users`, { cache: 'no-store' });
      if (!refreshed.ok) throw new Error('Account created, but the list could not refresh.');
      setAccounts((await refreshed.json()).users);
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }
  return <>
    <p className="notice notice-warning">{profile === 'hardened'
      ? 'Hardened: salted scrypt hashes only. No password hints or original password lengths are stored. Passwords cannot be revealed by this page.'
      : 'Baseline demonstration: salted PBKDF2 hashes plus an insecure support hint revealing the final two characters. The fixed mask does not show the original password length.'}</p>
    <p className="panel-description">Every account gets a random salt, so the same password produces different hashes. Hashes have a fixed format; their length does not reveal password length. Stored hashes are shown only to administrators for this lab.</p>
    {message && <p role="status" className="notice">{message}</p>}
    {error && <p role="alert" className="notice notice-error">{error}</p>}
    <section className="lab-panel guided-demo"><div className="panel-heading"><h2>Accounts and password storage.</h2></div>
      <div className="lab-table-wrap"><table className="lab-table"><thead><tr><th>Username</th><th>Role</th><th>Password visibility</th><th>Storage</th></tr></thead><tbody>{accounts.map(account => <tr key={account.username}>
        <td>{account.username}</td><td>{account.role}</td><td>{account.legacy_hint ?? 'Not recoverable through the application'}{account.legacy_hint && <p>Deliberate baseline information leak</p>}</td>
        <td>{account.method}<p>Random salt: {account.salt_characters} characters</p><details><summary>Inspect stored hash</summary><code style={{overflowWrap:'anywhere'}}>{account.password_hash}</code></details></td>
      </tr>)}</tbody></table></div>
    </section>
    <section className="lab-panel"><div className="panel-heading"><h2>Add an account.</h2></div>
      <p className="panel-description">Creates an account in the selected profile only. Operators can use the home and lab; administrators can also list and create accounts.</p>
      <form className="signin-form" onSubmit={create} autoComplete="off">
        <label htmlFor="new-username">Username<input id="new-username" value={username} onChange={e => setUsername(e.target.value)} pattern="[a-zA-Z0-9_.\-]{3,32}" required autoComplete="off" /></label>
        <label htmlFor="new-password">Password<input id="new-password" type="password" value={password} onChange={e => setPassword(e.target.value)} minLength={8} maxLength={128} required autoComplete="new-password" /></label>
        <label htmlFor="new-role">Role<select id="new-role" value={role} onChange={e => setRole(e.target.value)}><option value="operator">Operator</option><option value="admin">Administrator</option></select></label>
        <button className="primary-button" disabled={busy}>{busy ? 'Creating…' : 'Create account'}</button>
      </form>
    </section>
  </>;
}

export default function Users() {
  const { mode } = useMode();
  const lab = useLab(mode, false);
  return <Layout><section className="workspace container-full">
    <div className="workspace-title"><div><p className="eyebrow">Administrator workspace</p><h1>People and access.</h1><p>Manage accounts and compare password storage.</p></div><ModeToggle /></div>
    {lab.session === 'checking' ? <p>Checking your session…</p> : lab.session !== 'authenticated' ? <p><Link to="/dashboard">Sign in to your home</Link> to manage accounts.</p> : lab.snapshot?.user?.role !== 'admin' ? <p role="alert">Administrator access required. <Link to="/dashboard">Return home.</Link></p> : <>
      <p>Signed in as {lab.snapshot.user.username} · {mode} profile · <Link to="/dashboard">Back to home</Link></p>
      <AccountManager key={mode} profile={mode} />
    </>}
  </section></Layout>;
}
