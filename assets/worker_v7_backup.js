// MedAdapt API Worker v7
// v9追加: NDA管理・退院通知・アクセス権限制御
// v8追加: モジュール権限チェック・通知・クーポン
// v6追加: /auth/reset で login_id にも対応
// Bindings: DB (D1), AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, FROM_EMAIL

export default {
  async fetch(request, env) {
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    };
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });

    const json = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status, headers: { ...cors, 'Content-Type': 'application/json' }
      });
    const err = (msg, status = 400) => json({ error: msg }, status);

    try {
      return await handleRequest(request, env, json, err);
    } catch (e) {
      console.error('Unhandled error:', e);
      return err('サーバーエラーが発生しました: ' + e.message, 500);
    }
  }
};

async function handleRequest(request, env, json, err) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  await initDB(env.DB);

  // ── POST /auth/register（法人管理者登録）──────────────────
  if (path === '/auth/register' && method === 'POST') {
    const { email, password, org, type, name, plan } = await request.json().catch(() => ({}));
    if (!password || !org || !name) return err('必須項目が不足しています（法人名・管理者名・パスワード）');
    if (password.length < 8) return err('パスワードは8文字以上で入力してください');

    let loginId, attempts = 0;
    while (attempts < 10) {
      loginId = genLoginId('ADM');
      const ex = await env.DB.prepare('SELECT id FROM users WHERE login_id=?').bind(loginId).first();
      if (!ex) break;
      attempts++;
    }

    const id = 'u_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5);
    const pwHash = await hashPassword(password);
    const now = new Date().toISOString();
    const hasEmail = !!(email && email.trim());
    const verifyToken = hasEmail ? crypto.randomUUID() : null;
    const emailVerified = hasEmail ? 0 : 1;

    await env.DB.prepare(
      'INSERT INTO users (id,login_id,email,pw,pw_hash,org,type,name,plan,usage,email_verified,verify_token,role,org_id,created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
    ).bind(id, loginId, email||'', '', pwHash, org, type||'', name, plan||'free', '{}', emailVerified, verifyToken, 'admin', id, now).run();

    // subscriptionsにmedical-adaptのレコードを自動作成
    try {
      await env.DB.prepare(
        'INSERT OR IGNORE INTO subscriptions (id,org_id,module_id,status,started_at,created_at) VALUES (?,?,?,?,?,?)'
      ).bind('sub_' + id, id, 'medical-adapt', 'active', now, now).run();
    } catch(e) { /* subscriptionsテーブルがない場合はスキップ */ }

    if (hasEmail && verifyToken) {
      const baseUrl = 'https://medadapt.scsgo.co.jp';
      const verifyUrl = `${baseUrl}/app.html?verify=${verifyToken}&login_id=${loginId}`;
      await sendEmail(env, {
        to: email.trim(),
        subject: '【MedAdapt】メールアドレスの確認',
        html: `
          <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:24px;">
            <h2 style="color:#0891b2;">MedAdaptへようこそ</h2>
            <p>${name} 様</p>
            <p>ご登録ありがとうございます。</p>
            <div style="background:#f0fdfa;border:1px solid #0891b2;border-radius:8px;padding:16px;margin:16px 0;text-align:center;">
              <div style="font-size:12px;color:#64748b;">あなたのログインIDは</div>
              <div style="font-size:28px;font-weight:900;color:#0891b2;letter-spacing:2px;">${loginId}</div>
              <div style="font-size:11px;color:#94a3b8;margin-top:4px;">このIDとパスワードでログインしてください</div>
            </div>
            <p>下記のボタンをクリックしてメールアドレスを確認してください。</p>
            <a href="${verifyUrl}" style="display:inline-block;padding:12px 24px;background:#0891b2;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;margin:16px 0;">メールアドレスを確認する</a>
            <p style="font-size:12px;color:#666;">このリンクは24時間有効です。</p>
            <hr style="border:none;border-top:1px solid #eee;margin:24px 0;">
            <p style="font-size:11px;color:#999;">タムジ.Corp | MedAdapt 医療介護連携OS</p>
          </div>
        `
      });
      return json({ success: true, login_id: loginId, message: '確認メールを送信しました' });
    }

    return json({ success: true, login_id: loginId, message: '登録完了' });
  }

  // ── GET /auth/verify ──────────────────────────────────────
  if (path === '/auth/verify' && method === 'GET') {
    const token = url.searchParams.get('token');
    const loginId = url.searchParams.get('login_id');
    const email = url.searchParams.get('email');
    if (!token) return err('無効なリクエストです');

    let user;
    if (loginId) {
      user = await env.DB.prepare('SELECT * FROM users WHERE login_id=? AND verify_token=?').bind(loginId, token).first();
      if (!user) return err('認証リンクが無効または期限切れです');
      await env.DB.prepare('UPDATE users SET email_verified=1, verify_token=NULL WHERE login_id=?').bind(loginId).run();
    } else if (email) {
      user = await env.DB.prepare('SELECT * FROM users WHERE email=? AND verify_token=?').bind(email, token).first();
      if (!user) return err('認証リンクが無効または期限切れです');
      await env.DB.prepare('UPDATE users SET email_verified=1, verify_token=NULL WHERE email=?').bind(email).run();
    } else {
      return err('無効なリクエストです');
    }
    return json({ success: true, login_id: user.login_id, message: 'メールアドレスの確認が完了しました' });
  }

  // ── POST /auth/resend-verify ──────────────────────────────
  if (path === '/auth/resend-verify' && method === 'POST') {
    const { email } = await request.json().catch(() => ({}));
    if (!email) return err('メールアドレスを入力してください');
    const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
    if (!user) return err('登録されていないメールアドレスです');
    if (user.email_verified) return err('既に認証済みです');
    const verifyToken = crypto.randomUUID();
    await env.DB.prepare('UPDATE users SET verify_token=? WHERE email=?').bind(verifyToken, email).run();
    const baseUrl = 'https://medadapt.scsgo.co.jp';
    const verifyUrl = `${baseUrl}/app.html?verify=${verifyToken}&email=${encodeURIComponent(email)}`;
    await sendEmail(env, {
      to: email,
      subject: '【MedAdapt】メールアドレスの確認（再送）',
      html: `
        <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:24px;">
          <h2 style="color:#0891b2;">確認メールの再送</h2>
          <p>下記のボタンをクリックしてメールアドレスを確認してください。</p>
          <a href="${verifyUrl}" style="display:inline-block;padding:12px 24px;background:#0891b2;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;margin:16px 0;">メールアドレスを確認する</a>
          <p style="font-size:12px;color:#666;">このリンクは24時間有効です。</p>
        </div>
      `
    });
    return json({ success: true });
  }

  // ── POST /auth/login ──────────────────────────────────────
  if (path === '/auth/login' && method === 'POST') {
    const { email, password } = await request.json().catch(() => ({}));
    if (!email || !password) return err('入力してください');

    let user;
    if (email.includes('-') && (email.startsWith('ADM') || email.startsWith('STF'))) {
      user = await env.DB.prepare('SELECT * FROM users WHERE login_id=?').bind(email.toUpperCase()).first();
    } else {
      user = await env.DB.prepare('SELECT * FROM users WHERE login_id=? OR email=?').bind(email.toUpperCase(), email).first();
    }
    if (!user) return err('ログインIDまたはパスワードが違います', 401);

    let pwOk = false;
    if (user.pw_hash) {
      pwOk = await verifyPassword(password, user.pw_hash);
    } else if (user.pw) {
      pwOk = (user.pw === password);
      if (pwOk) {
        const pwHash = await hashPassword(password);
        await env.DB.prepare('UPDATE users SET pw_hash=?, pw=NULL WHERE id=?').bind(pwHash, user.id).run();
      }
    }
    if (!pwOk) return err('ログインIDまたはパスワードが違います', 401);
    if (!user.email_verified) return err('メールアドレスが未確認です。届いた確認メールのリンクをクリックしてください。', 403);
    if (user.suspended) return err('このアカウントは停止されています。管理者にお問い合わせください。', 403);

    const token = crypto.randomUUID();
    const expires = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString();
    await env.DB.prepare('INSERT OR REPLACE INTO sessions (token,email,user_login_id,created,expires) VALUES (?,?,?,?,?)')
      .bind(token, user.id, user.login_id||'', new Date().toISOString(), expires).run();

    // last_login_at を更新
    try {
      const now = new Date().toISOString();
      await env.DB.prepare('UPDATE users SET last_login_at=? WHERE id=?').bind(now, user.id).run();
      // active_staff_log に当月レコードをINSERT（重複は無視）
      const loginMonth = now.slice(0, 7);
      await env.DB.prepare(
        'INSERT OR IGNORE INTO active_staff_log (id,org_id,user_id,login_month,first_login) VALUES (?,?,?,?,?)'
      ).bind(crypto.randomUUID(), user.org_id || user.id, user.id, loginMonth, now).run();
    } catch(e) { /* テーブルがない場合はスキップ */ }

    // owner_email をレスポンスに含める（スタッフの場合は法人adminのemail）
    let ownerEmail = user.email;
    if (user.role === 'staff') {
      const adminUser = await env.DB.prepare('SELECT email FROM users WHERE id=? AND role=?').bind(user.org_id, 'admin').first();
      if (adminUser) ownerEmail = adminUser.email;
    }

    const userOut = {
      ...user,
      pw: undefined, pw_hash: undefined, verify_token: undefined, reset_token: undefined,
      usage: JSON.parse(user.usage || '{}'),
      owner_email: ownerEmail
    };
    return json({ token, user: userOut });
  }

  // ── POST /auth/reset-request ──────────────────────────────
  if (path === '/auth/reset-request' && method === 'POST') {
    const { email } = await request.json().catch(() => ({}));
    if (!email) return err('メールアドレスを入力してください');
    const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
    if (user) {
      const resetToken = crypto.randomUUID();
      const resetExpires = new Date(Date.now() + 60 * 60 * 1000).toISOString();
      await env.DB.prepare('UPDATE users SET reset_token=?, reset_expires=? WHERE email=?')
        .bind(resetToken, resetExpires, email).run();
      const baseUrl = 'https://medadapt.scsgo.co.jp';
      // login_id があればURLに含める（新しいリセット画面対応）
      const resetUrl = user.login_id
        ? `${baseUrl}/app.html?reset=${resetToken}&login_id=${user.login_id}`
        : `${baseUrl}/app.html?reset=${resetToken}&email=${encodeURIComponent(email)}`;
      await sendEmail(env, {
        to: email,
        subject: '【MedAdapt】パスワードリセット',
        html: `
          <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:24px;">
            <h2 style="color:#0891b2;">パスワードリセット</h2>
            ${user.login_id ? `<p>ログインID: <strong>${user.login_id}</strong></p>` : ''}
            <p>下記のボタンをクリックして新しいパスワードを設定してください。</p>
            <a href="${resetUrl}" style="display:inline-block;padding:12px 24px;background:#0891b2;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;margin:16px 0;">パスワードをリセットする</a>
            <p style="font-size:12px;color:#666;">このリンクは1時間有効です。</p>
          </div>
        `
      });
    }
    return json({ success: true, message: 'リセット用メールを送信しました（登録済みの場合）' });
  }

  // ── POST /auth/reset ──────────────────────────────────────
  if (path === '/auth/reset' && method === 'POST') {
    const { email, login_id, token, newPassword } = await request.json().catch(() => ({}));
    if (!token || !newPassword) return err('必須項目が不足しています');
    if (newPassword.length < 6) return err('パスワードは6文字以上で入力してください');

    let user;
    if (login_id) {
      user = await env.DB.prepare('SELECT * FROM users WHERE login_id=? AND reset_token=?').bind(login_id, token).first();
    } else if (email) {
      user = await env.DB.prepare('SELECT * FROM users WHERE email=? AND reset_token=?').bind(email, token).first();
    } else {
      return err('login_id または email が必要です');
    }
    if (!user) return err('リセットリンクが無効です');
    if (new Date(user.reset_expires) < new Date()) return err('リセットリンクの有効期限が切れています');

    const pwHash = await hashPassword(newPassword);
    await env.DB.prepare('UPDATE users SET pw_hash=?, pw=NULL, reset_token=NULL, reset_expires=NULL WHERE id=?')
      .bind(pwHash, user.id).run();
    return json({ success: true, message: 'パスワードを変更しました' });
  }

  // ── GET /invite/:token（招待トークン確認・認証不要）────────
  if (path.startsWith('/invite/') && method === 'GET') {
    const inviteToken = path.replace('/invite/', '');
    const invite = await env.DB.prepare('SELECT * FROM invites WHERE token=? AND used=0').bind(inviteToken).first();
    if (!invite) return err('招待リンクが無効または使用済みです');
    if (new Date(invite.expires) < new Date()) return err('招待リンクの有効期限が切れています（7日間有効）');
    return json({ org_id: invite.org_id, org_name: invite.org_name, email: invite.email });
  }

  // ── POST /auth/staff-register（スタッフ登録・認証不要）────
  if (path === '/auth/staff-register' && method === 'POST') {
    const { invite_token, email, password, name } = await request.json().catch(() => ({}));
    if (!invite_token || !password || !name) return err('必須項目が不足しています（名前・パスワード）');
    if (password.length < 6) return err('パスワードは6文字以上');

    const invite = await env.DB.prepare('SELECT * FROM invites WHERE token=? AND used=0').bind(invite_token).first();
    if (!invite) return err('招待リンクが無効または使用済みです');
    if (new Date(invite.expires) < new Date()) return err('招待リンクの有効期限が切れています');

    const adminUser = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(invite.org_id).first();
    if (!adminUser) return err('法人情報が見つかりません');

    let loginId, attempts = 0;
    while (attempts < 10) {
      loginId = genLoginId('STF');
      const ex = await env.DB.prepare('SELECT id FROM users WHERE login_id=?').bind(loginId).first();
      if (!ex) break;
      attempts++;
    }

    const id = 'u_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5);
    const pwHash = await hashPassword(password);
    const now = new Date().toISOString();
    const hasEmail = !!(email && email.trim());

    await env.DB.prepare(
      'INSERT INTO users (id,login_id,email,pw,pw_hash,org,type,name,plan,usage,email_verified,role,org_id,created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
    ).bind(id, loginId, email||'', '', pwHash, adminUser.org, adminUser.type||'', name, 'staff', '{}', 1, 'staff', invite.org_id, now).run();

    await env.DB.prepare('UPDATE invites SET used=1 WHERE token=?').bind(invite_token).run();

    if (hasEmail) {
      try {
        await sendEmail(env, {
          to: email.trim(),
          subject: `【MedAdapt】スタッフ登録完了 - あなたのログインID`,
          html: `
            <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:24px;">
              <h2 style="color:#0891b2;">スタッフ登録完了</h2>
              <p>${name} 様</p>
              <p>${adminUser.org} のMedAdaptへの登録が完了しました。</p>
              <div style="background:#f0fdfa;border:1px solid #0891b2;border-radius:8px;padding:16px;margin:16px 0;text-align:center;">
                <div style="font-size:12px;color:#64748b;">あなたのログインIDは</div>
                <div style="font-size:28px;font-weight:900;color:#0891b2;letter-spacing:2px;">${loginId}</div>
              </div>
              <p style="font-size:12px;color:#666;">ログインURL: https://medadapt.scsgo.co.jp/app.html</p>
            </div>
          `
        });
      } catch(e) { console.error('Staff notify email error:', e); }
    }

    return json({ success: true, login_id: loginId, message: 'スタッフ登録完了' });
  }

  // ── POST /auth/qr-login（QRコードでログイン・認証不要）────
  if (path === '/auth/qr-login' && method === 'POST') {
    const { qr_token } = await request.json().catch(() => ({}));
    if (!qr_token) return err('qr_tokenが必要です');
    const user = await env.DB.prepare('SELECT * FROM users WHERE qr_token=?').bind(qr_token).first();
    if (!user) return err('無効なQRコードです', 401);
    if (user.suspended) return err('このアカウントは停止されています', 403);
    const token = crypto.randomUUID();
    const expires = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString();
    await env.DB.prepare('INSERT OR REPLACE INTO sessions (token,email,user_login_id,created,expires) VALUES (?,?,?,?,?)')
      .bind(token, user.id, user.login_id||'', new Date().toISOString(), expires).run();
    const userOut = { ...user, pw: undefined, pw_hash: undefined, verify_token: undefined, reset_token: undefined, qr_token: undefined, usage: JSON.parse(user.usage || '{}') };
    return json({ token, user: userOut });
  }

  // ── v8: GET /modules/:moduleId/access（モジュール利用権チェック・認証不要でも動作）──
  if (path.match(/^\/modules\/[^/]+\/access$/) && method === 'GET') {
    const moduleId = path.split('/')[2];
    const authHeader = request.headers.get('Authorization') || '';
    const accessToken = authHeader.replace('Bearer ', '').trim();
    if (!accessToken) return json({ access: true, status: 'free', compat: true });

    const session = await env.DB.prepare('SELECT * FROM sessions WHERE token=? AND expires>?').bind(accessToken, new Date().toISOString()).first();
    if (!session) return json({ access: true, status: 'free', compat: true });
    const user = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(session.email).first();
    if (!user) return json({ access: true, status: 'free', compat: true });

    // subscriptionsテーブルを確認
    let sub = null;
    try {
      sub = await env.DB.prepare('SELECT * FROM subscriptions WHERE org_id=? AND module_id=? AND cancelled_at IS NULL').bind(user.org_id || user.id, moduleId).first();
    } catch(e) { /* テーブルがない場合はスキップ */ }

    if (!sub) {
      // 後方互換: usersのplanで判定
      if (user.plan === 'pro' || user.plan === 'staff' || user.role === 'staff') {
        return json({ access: true, status: 'active', compat: true });
      }
      return json({ access: true, status: 'free', compat: true });
    }

    const now = new Date().toISOString();
    if (sub.trial_end_at && sub.trial_end_at > now) {
      return json({ access: true, status: 'trial', trial_end_at: sub.trial_end_at });
    }
    if (sub.status === 'active') return json({ access: true, status: 'active' });
    if (sub.status === 'suspended') return json({ access: false, reason: 'payment_failed', status: 'suspended' });
    if (sub.status === 'cancelled') return json({ access: false, reason: 'cancelled' });
    return json({ access: true, status: sub.status });
  }

  // ── Token認証 ─────────────────────────────────────────────
  const authHeader = request.headers.get('Authorization') || '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (!token) return err('認証が必要です', 401);
  const session = await env.DB.prepare('SELECT * FROM sessions WHERE token=?').bind(token).first();
  if (!session || new Date(session.expires) < new Date()) return err('セッションが切れています', 401);
  const userId = session.email;
  const currentUser = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(userId).first();
  if (!currentUser) return err('ユーザーが見つかりません', 401);
  const currentEmail = currentUser.email;

  // ── v8: GET /notifications/unread ────────────────────────
  if (path === '/notifications/unread' && method === 'GET') {
    let count = 0;
    try {
      const result = await env.DB.prepare('SELECT COUNT(*) as count FROM notifications WHERE user_id=? AND is_read=0').bind(currentUser.id).first();
      count = result?.count || 0;
    } catch(e) { /* テーブルがない場合は0を返す */ }
    return json({ count });
  }

  // ── v8: GET /notifications ────────────────────────────────
  if (path === '/notifications' && method === 'GET') {
    let notifs = [];
    try {
      const result = await env.DB.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 30').bind(currentUser.id).all();
      notifs = result.results || [];
    } catch(e) { /* テーブルがない場合は空配列 */ }
    return json({ notifications: notifs });
  }

  // ── v8: POST /notifications/read-all ─────────────────────
  if (path === '/notifications/read-all' && method === 'POST') {
    try {
      await env.DB.prepare('UPDATE notifications SET is_read=1, read_at=? WHERE user_id=? AND is_read=0').bind(new Date().toISOString(), currentUser.id).run();
    } catch(e) {}
    return json({ success: true });
  }

  // ── v8: POST /notifications/:id/read ─────────────────────
  if (path.match(/^\/notifications\/[^/]+\/read$/) && method === 'POST') {
    const notifId = path.split('/')[2];
    try {
      await env.DB.prepare('UPDATE notifications SET is_read=1, read_at=? WHERE id=? AND user_id=?').bind(new Date().toISOString(), notifId, currentUser.id).run();
    } catch(e) {}
    return json({ success: true });
  }

  // ── v8: POST /coupons/apply ───────────────────────────────
  if (path === '/coupons/apply' && method === 'POST') {
    const { coupon_code, module_id } = await request.json().catch(() => ({}));
    if (!coupon_code) return err('クーポンコードを入力してください');

    let coupon = null;
    try {
      coupon = await env.DB.prepare('SELECT * FROM coupons WHERE code=? AND is_active=1').bind(coupon_code).first();
    } catch(e) { return err('クーポン機能は現在利用できません'); }
    if (!coupon) return err('無効なクーポンコードです');

    const now = new Date().toISOString();
    if (coupon.valid_until && coupon.valid_until < now) return err('このクーポンは期限切れです');
    if (coupon.valid_from > now) return err('このクーポンはまだ使用できません');
    if (coupon.max_uses && coupon.used_count >= coupon.max_uses) return err('使用上限に達しています');

    const orgId = currentUser.org_id || currentUser.id;
    const used = await env.DB.prepare('SELECT id FROM coupon_usages WHERE coupon_id=? AND org_id=?').bind(coupon.id, orgId).first();
    if (used) return err('このクーポンは既に使用済みです');
    if (coupon.target_module_id && module_id && coupon.target_module_id !== module_id) return err('このクーポンはこのモジュールには使用できません');

    let sub = await env.DB.prepare('SELECT * FROM subscriptions WHERE org_id=? AND module_id=?').bind(orgId, module_id || 'medical-adapt').first().catch(() => null);
    if (!sub) {
      const subId = 'sub_' + Date.now().toString(36);
      await env.DB.prepare('INSERT INTO subscriptions (id,org_id,module_id,status,started_at,created_at) VALUES (?,?,?,?,?,?)').bind(subId, orgId, module_id || 'medical-adapt', 'trial', now, now).run().catch(() => {});
      sub = { id: subId };
    }

    if (coupon.discount_type === 'free_months') {
      const trialEnd = new Date();
      trialEnd.setMonth(trialEnd.getMonth() + coupon.discount_value);
      await env.DB.prepare('UPDATE subscriptions SET trial_end_at=?, coupon_code=?, free_months_remaining=?, status=? WHERE id=?').bind(trialEnd.toISOString(), coupon_code, coupon.discount_value, 'trial', sub.id).run().catch(() => {});
    }

    await env.DB.prepare('INSERT INTO coupon_usages (id,coupon_id,org_id,used_at,applied_to) VALUES (?,?,?,?,?)').bind(crypto.randomUUID(), coupon.id, orgId, now, sub.id).run().catch(() => {});
    await env.DB.prepare('UPDATE coupons SET used_count=used_count+1 WHERE id=?').bind(coupon.id).run().catch(() => {});

    return json({ success: true, message: `${coupon.name}が適用されました！` });
  }

  // ── POST /staff/invite（招待リンク発行・adminのみ）─────────
  if (path === '/staff/invite' && method === 'POST') {
    if (currentUser.role !== 'admin') return err('管理者のみ実行できます', 403);
    const { email } = await request.json().catch(() => ({}));
    const inviteToken = crypto.randomUUID();
    const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    const id = 'inv_' + Date.now().toString(36);
    const now = new Date().toISOString();
    await env.DB.prepare('INSERT INTO invites (id,org_id,org_name,email,token,expires,used,created) VALUES (?,?,?,?,?,?,?,?)')
      .bind(id, currentUser.org_id || currentUser.id, currentUser.org, email || '', inviteToken, expires, 0, now).run();
    const baseUrl = 'https://medadapt.scsgo.co.jp';
    const inviteUrl = `${baseUrl}/app.html?invite=${inviteToken}`;
    if (email) {
      await sendEmail(env, {
        to: email,
        subject: `【MedAdapt】${currentUser.org}からスタッフ招待が届いています`,
        html: `
          <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:24px;">
            <h2 style="color:#0891b2;">MedAdaptへの招待</h2>
            <p>${currentUser.org} の管理者からMedAdaptへの招待が届いています。</p>
            <a href="${inviteUrl}" style="display:inline-block;padding:12px 24px;background:#0891b2;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;margin:16px 0;">アカウントを作成する</a>
            <p style="font-size:12px;color:#666;">このリンクは7日間有効です。</p>
          </div>
        `
      });
    }
    return json({ success: true, invite_url: inviteUrl, token: inviteToken });
  }

  // ── GET /staff ────────────────────────────────────────────
  if (path === '/staff' && method === 'GET') {
    if (currentUser.role !== 'admin') return err('管理者のみ実行できます', 403);
    const orgId = currentUser.org_id || currentUser.id;
    const staff = await env.DB.prepare(
      "SELECT id,login_id,email,name,role,plan,email_verified,suspended,created FROM users WHERE org_id=? AND role='staff' ORDER BY created ASC"
    ).bind(orgId).all();
    return json({ staff: staff.results });
  }

  // ── POST /staff/reset-password ────────────────────────────
  if (path === '/staff/reset-password' && method === 'POST') {
    if (currentUser.role !== 'admin') return err('管理者のみ実行できます', 403);
    const { staff_id } = await request.json().catch(() => ({}));
    if (!staff_id) return err('staff_idが必要です');
    const orgId = currentUser.org_id || currentUser.id;
    const target = await env.DB.prepare('SELECT * FROM users WHERE id=? AND org_id=?').bind(staff_id, orgId).first();
    if (!target) return err('対象スタッフが見つかりません');
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    let newPw = '';
    for (let i = 0; i < 8; i++) newPw += chars[Math.floor(Math.random() * chars.length)];
    const pwHash = await hashPassword(newPw);
    await env.DB.prepare('UPDATE users SET pw_hash=?, pw=NULL WHERE id=?').bind(pwHash, staff_id).run();
    await env.DB.prepare('DELETE FROM sessions WHERE email=?').bind(target.id).run();
    return json({ success: true, new_password: newPw, login_id: target.login_id, name: target.name });
  }

  // ── POST /staff/qr ────────────────────────────────────────
  if (path === '/staff/qr' && method === 'POST') {
    if (currentUser.role !== 'admin') return err('管理者のみ実行できます', 403);
    const { staff_id } = await request.json().catch(() => ({}));
    if (!staff_id) return err('staff_idが必要です');
    const orgId = currentUser.org_id || currentUser.id;
    const target = await env.DB.prepare('SELECT * FROM users WHERE id=? AND org_id=?').bind(staff_id, orgId).first();
    if (!target) return err('対象スタッフが見つかりません');
    const qrToken = crypto.randomUUID().replace(/-/g,'') + crypto.randomUUID().replace(/-/g,'');
    await env.DB.prepare('UPDATE users SET qr_token=? WHERE id=?').bind(qrToken, staff_id).run();
    const baseUrl = 'https://medadapt.scsgo.co.jp';
    const qrUrl = `${baseUrl}/app.html?qr=${qrToken}`;
    return json({ success: true, qr_url: qrUrl, qr_token: qrToken });
  }

  // ── POST /staff/suspend ───────────────────────────────────
  if (path === '/staff/suspend' && method === 'POST') {
    if (currentUser.role !== 'admin') return err('管理者のみ実行できます', 403);
    const { staff_id, suspend } = await request.json().catch(() => ({}));
    if (!staff_id) return err('staff_idが必要です');
    const orgId = currentUser.org_id || currentUser.id;
    const target = await env.DB.prepare('SELECT * FROM users WHERE id=? AND org_id=?').bind(staff_id, orgId).first();
    if (!target) return err('対象スタッフが見つかりません');
    await env.DB.prepare('UPDATE users SET suspended=? WHERE id=?').bind(suspend ? 1 : 0, staff_id).run();
    if (suspend) await env.DB.prepare('DELETE FROM sessions WHERE email=?').bind(target.id).run();
    return json({ success: true });
  }

  // ── DELETE /staff/:id ─────────────────────────────────────
  if (path.startsWith('/staff/') && method === 'DELETE') {
    if (currentUser.role !== 'admin') return err('管理者のみ実行できます', 403);
    const staffId = path.replace('/staff/', '');
    const orgId = currentUser.org_id || currentUser.id;
    const target = await env.DB.prepare('SELECT * FROM users WHERE id=? AND org_id=?').bind(staffId, orgId).first();
    if (!target) return err('対象スタッフが見つかりません');
    await env.DB.prepare('DELETE FROM sessions WHERE email=?').bind(target.id).run();
    await env.DB.prepare('DELETE FROM users WHERE id=?').bind(staffId).run();
    return json({ success: true });
  }

  // ── GET /sync ─────────────────────────────────────────────
  if (path === '/sync' && method === 'GET') {
    const orgId = currentUser.org_id || currentUser.id;
    let ownerEmail;
    if (currentUser.role === 'admin') {
      ownerEmail = currentUser.email;
    } else {
      const adminUser = await env.DB.prepare('SELECT email FROM users WHERE id=? AND role=?').bind(orgId, 'admin').first();
      ownerEmail = adminUser?.email || currentUser.email;
    }
    const [patients, cases, conferences, monitors, assessments] = await Promise.all([
      env.DB.prepare('SELECT data FROM patients WHERE owner_email=?').bind(ownerEmail).all(),
      env.DB.prepare('SELECT data FROM cases WHERE owner_email=?').bind(ownerEmail).all(),
      env.DB.prepare('SELECT data FROM conferences WHERE owner_email=?').bind(ownerEmail).all(),
      env.DB.prepare('SELECT data FROM monitors WHERE owner_email=?').bind(ownerEmail).all(),
      env.DB.prepare('SELECT data FROM assessments WHERE owner_email=?').bind(ownerEmail).all(),
    ]);

    // owner_email をレスポンスに含める
    let ownerEmailForClient = currentUser.email;
    if (currentUser.role === 'staff') ownerEmailForClient = ownerEmail;

    const userOut = {
      ...currentUser,
      pw: undefined, pw_hash: undefined, verify_token: undefined, reset_token: undefined,
      usage: JSON.parse(currentUser.usage || '{}'),
      owner_email: ownerEmailForClient
    };
    return json({
      patients: patients.results.map(r => safeJson(r.data)),
      cases: cases.results.map(r => safeJson(r.data)),
      conferences: conferences.results.map(r => safeJson(r.data)),
      monitors: monitors.results.map(r => safeJson(r.data)),
      assessments: assessments.results.map(r => safeJson(r.data)),
      user: userOut,
    });
  }

  // ── POST /sync ────────────────────────────────────────────
  if (path === '/sync' && method === 'POST') {
    const D = await request.json().catch(() => ({}));
    const now = new Date().toISOString();
    const stmts = [];
    const orgId = currentUser.org_id || currentUser.id;
    const adminUser = currentUser.role === 'admin' ? currentUser :
      await env.DB.prepare('SELECT * FROM users WHERE id=? AND role=?').bind(orgId, 'admin').first();
    const ownerEmail = adminUser ? adminUser.email : currentUser.email;

    const upsert = (table, id, extra, data) => {
      const keys = Object.keys(extra);
      const cols = ['id', 'owner_email', ...keys, 'data', 'updated'];
      const vals = [id, ownerEmail, ...keys.map(k => extra[k]), JSON.stringify(data), now];
      const placeholders = vals.map(() => '?').join(',');
      const onConflict = [...keys.map(k => `${k}=excluded.${k}`), 'data=excluded.data', 'updated=excluded.updated'].join(',');
      return env.DB.prepare(`INSERT INTO ${table} (${cols.join(',')}) VALUES (${placeholders}) ON CONFLICT(id) DO UPDATE SET ${onConflict}`).bind(...vals);
    };

    if (Array.isArray(D.patients)) for (const p of D.patients) { if (p.id) stmts.push(upsert('patients', p.id, { created: p.created || now }, p)); }
    if (Array.isArray(D.cases)) for (const c of D.cases) { if (c.id) stmts.push(upsert('cases', c.id, { patient_id: c.patientId || '', created: c.created || now }, c)); }
    if (Array.isArray(D.conferences)) for (const c of D.conferences) { if (c.id) stmts.push(upsert('conferences', c.id, { patient_id: c.patientId || '', created: c.created || now }, c)); }
    if (Array.isArray(D.monitors)) for (const m of D.monitors) { if (m.id) stmts.push(upsert('monitors', m.id, { patient_id: m.patientId || '', created: m.created || now }, m)); }
    if (Array.isArray(D.assessments)) for (const a of D.assessments) { if (a.id) stmts.push(upsert('assessments', a.id, { patient_id: a.patientId || '', created: a.created || now }, a)); }

    for (let i = 0; i < stmts.length; i += 100) await env.DB.batch(stmts.slice(i, i + 100));
    return json({ success: true, saved: stmts.length });
  }

  // ── POST /documents ───────────────────────────────────────
  if (path === '/documents' && method === 'POST') {
    const doc = await request.json().catch(() => ({}));
    if (!doc.patientId || !doc.docType) return err('patientId, docType は必須です');
    const id = 'doc_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5);
    const now = new Date().toISOString();
    await env.DB.prepare('INSERT INTO documents (id,patient_id,related_id,owner_email,doc_type,title,content,created_by,created) VALUES (?,?,?,?,?,?,?,?,?)')
      .bind(id, doc.patientId, doc.relatedId || '', currentEmail, doc.docType, doc.title || '', JSON.stringify(doc.content || {}), doc.createdBy || currentUser.name || '', now).run();
    return json({ id, created: now });
  }

  // ── GET /documents ────────────────────────────────────────
  if (path === '/documents' && method === 'GET') {
    const patientId = url.searchParams.get('patient_id');
    const rows = patientId
      ? await env.DB.prepare('SELECT id,patient_id,related_id,doc_type,title,created_by,created FROM documents WHERE owner_email=? AND patient_id=? ORDER BY created DESC').bind(currentEmail, patientId).all()
      : await env.DB.prepare('SELECT id,patient_id,related_id,doc_type,title,created_by,created FROM documents WHERE owner_email=? ORDER BY created DESC').bind(currentEmail).all();
    return json({ documents: rows.results });
  }

  // ── GET /documents/:id ────────────────────────────────────
  if (path.startsWith('/documents/') && method === 'GET') {
    const docId = path.replace('/documents/', '');
    const doc = await env.DB.prepare('SELECT * FROM documents WHERE id=? AND owner_email=?').bind(docId, currentEmail).first();
    if (!doc) return err('見つかりません', 404);
    return json({ ...doc, content: safeJson(doc.content) });
  }

  // ── DELETE /documents/:id ─────────────────────────────────
  if (path.startsWith('/documents/') && method === 'DELETE') {
    const docId = path.replace('/documents/', '');
    await env.DB.prepare('DELETE FROM documents WHERE id=? AND owner_email=?').bind(docId, currentEmail).run();
    return json({ success: true });
  }

  // ── POST /auth/change-password ────────────────────────────
  if (path === '/auth/change-password' && method === 'POST') {
    const { currentPassword, newPassword } = await request.json().catch(() => ({}));
    if (!newPassword || newPassword.length < 6) return err('新しいパスワードは6文字以上');
    if (currentPassword) {
      const ok = currentUser.pw_hash ? await verifyPassword(currentPassword, currentUser.pw_hash) : currentUser.pw === currentPassword;
      if (!ok) return err('現在のパスワードが違います');
    }
    const pwHash = await hashPassword(newPassword);
    await env.DB.prepare('UPDATE users SET pw_hash=?, pw=NULL WHERE id=?').bind(pwHash, currentUser.id).run();
    return json({ success: true });
  }


  // ═══════════════════════════════════════════════
  // v9: NDA管理 API
  // ═══════════════════════════════════════════════

  // GET /nda/list
  if (path === '/nda/list' && method === 'GET') {
    const orgId = currentUser.org_id || currentUser.id;
    let ndas = [];
    try {
      // paper_file_dataは重いので除外し、has_fileフラグのみ返す
      const result = await env.DB.prepare(
        'SELECT id,org_id_a,org_id_b,status,requested_at,signed_at,signed_by,signed_ip,signer_name,signer_role,terminated_at,nda_type,custom_text,form_type,paper_note,paper_file_type FROM org_ndas WHERE org_id_a=? OR org_id_b=? ORDER BY requested_at DESC'
      ).bind(orgId, orgId).all();
      ndas = result.results || [];
      // has_fileフラグを別クエリで取得
      for (const nda of ndas) {
        const partnerId = nda.org_id_a === orgId ? nda.org_id_b : nda.org_id_a;
        const partner = await env.DB.prepare(
          'SELECT login_id, org FROM users WHERE (org_id=? OR id=?) AND role=?'
        ).bind(partnerId, partnerId, 'admin').first();
        nda.partner_login_id = partner?.login_id || '';
        nda.partner_org = partner?.org || '';
        nda.is_requester = nda.org_id_a === orgId;
        // ファイル有無チェック
        const fileCheck = await env.DB.prepare(
          'SELECT (paper_file_data IS NOT NULL AND paper_file_data != \'\') as has_file FROM org_ndas WHERE id=?'
        ).bind(nda.id).first();
        nda.has_file = !!(fileCheck?.has_file);
      }
    } catch(e) { console.error('nda/list error:', e); }
    return json({ ndas });
  }

  // GET /nda/:id/file
  if (path.match(/^\/nda\/[^/]+\/file$/) && method === 'GET') {
    const ndaId = path.split('/')[2];
    const orgId = currentUser.org_id || currentUser.id;
    let row = null;
    try { row = await env.DB.prepare('SELECT paper_file_data, paper_file_type FROM org_ndas WHERE id=? AND (org_id_a=? OR org_id_b=?)').bind(ndaId, orgId, orgId).first(); } catch(e) {}
    if (!row?.paper_file_data) return err('ファイルが見つかりません', 404);
    return json({ data: row.paper_file_data, file_type: row.paper_file_type });
  }

  // POST /nda/request
  if (path === '/nda/request' && method === 'POST') {
    const { partner_login_id, nda_type, custom_text, form_type, paper_signed_at, paper_note, paper_file_data, paper_file_type } = await request.json().catch(() => ({}));
    if (!partner_login_id) return err('相手のログインIDを入力してください');
    const orgId = currentUser.org_id || currentUser.id;
    const partner = await env.DB.prepare(
      'SELECT * FROM users WHERE login_id=? AND role=?'
    ).bind(partner_login_id.toUpperCase(), 'admin').first();
    if (!partner) return err('該当するアカウントが見つかりません');
    const partnerId = partner.org_id || partner.id;
    if (partnerId === orgId) return err('自法人には申請できません');
    // 重複チェックなし（同一法人間で複数締結可能）
    const id = 'nda_' + Date.now().toString(36) + Math.random().toString(36).slice(2,5);
    const now = new Date().toISOString();
    const type = nda_type || 'standard';

    // 紙締結済み：即座にactiveで保存
    if (type === 'paper') {
      if (!paper_signed_at) return err('締結日を入力してください');
      try {
        await env.DB.prepare(
          'INSERT INTO org_ndas (id,org_id_a,org_id_b,status,requested_at,signed_at,nda_type,paper_note,paper_file_data,paper_file_type) VALUES (?,?,?,?,?,?,?,?,?,?)'
        ).bind(id, orgId, partnerId, 'active', now, paper_signed_at+'T00:00:00.000Z', 'paper', paper_note||'', paper_file_data||'', paper_file_type||'').run();
      } catch(e) { return err('記録に失敗しました: '+e.message); }
      try {
        await env.DB.prepare(
          'INSERT INTO notifications (id,user_id,module_id,type,title,body,action_url,is_read,created_at) VALUES (?,?,?,?,?,?,?,?,?)'
        ).bind('notif_'+Date.now().toString(36)+Math.random().toString(36).slice(2,4), partnerId,
          'medical-adapt','nda_signed',
          '【NDA記録】'+(currentUser.org||currentUser.login_id)+'が紙締結NDAを登録しました',
          '退院通知の送受信が可能になりました。', '#page:nda', 0, now).run();
      } catch(e) {}
      return json({ success: true, message: '紙締結NDAを記録しました。退院通知の送受信が可能になりました。' });
    }

    // 標準・カスタム：pending申請
    try {
      await env.DB.prepare(
        'INSERT INTO org_ndas (id,org_id_a,org_id_b,status,requested_at,nda_type,custom_text,form_type) VALUES (?,?,?,?,?,?,?,?)'
      ).bind(id, orgId, partnerId, 'pending', now, type, custom_text||'', form_type||'bilateral').run();
    } catch(e) { return err('NDA申請の送信に失敗しました: '+e.message); }
    const notifBody = type==='custom'
      ? '自社書式のNDAに署名することで退院通知の送受信が可能になります。'
      : 'MedAdapt上でNDAに署名することで退院通知の送受信が可能になります。';
    try {
      await env.DB.prepare(
        'INSERT INTO notifications (id,user_id,module_id,type,title,body,action_url,is_read,created_at) VALUES (?,?,?,?,?,?,?,?,?)'
      ).bind('notif_'+Date.now().toString(36)+Math.random().toString(36).slice(2,4), partnerId,
        'medical-adapt','nda_request',
        '【NDA申請】'+(currentUser.org||currentUser.login_id)+'からNDA締結申請が届いています',
        notifBody, '#page:nda', 0, now).run();
    } catch(e) {}
    return json({ success: true, message: 'NDA締結申請を送信しました' });
  }

  // POST /nda/sign
  if (path === '/nda/sign' && method === 'POST') {
    const { nda_id, password, signer_name, signer_role } = await request.json().catch(() => ({}));
    if (!nda_id) return err('nda_idが必要です');
    // 本人確認：パスワード検証
    if (!password) return err('本人確認のためパスワードを入力してください');
    if (!signer_name) return err('署名者氏名を入力してください');
    const pwOk = currentUser.pw_hash
      ? await verifyPassword(password, currentUser.pw_hash)
      : (currentUser.pw === password);
    if (!pwOk) return err('パスワードが正しくありません。本人確認に失敗しました。');
    const orgId = currentUser.org_id || currentUser.id;
    let nda = null;
    try { nda = await env.DB.prepare('SELECT * FROM org_ndas WHERE id=?').bind(nda_id).first(); } catch(e) {}
    if (!nda) return err('NDAが見つかりません');
    if (nda.org_id_b !== orgId) return err('この申請に署名する権限がありません');
    if (nda.status === 'active') return err('既に締結済みです');
    const now = new Date().toISOString();
    const ip = request.headers.get('CF-Connecting-IP') || '';
    try {
      await env.DB.prepare(
        'UPDATE org_ndas SET status=?,signed_at=?,signed_by=?,signed_ip=?,signer_name=?,signer_role=? WHERE id=?'
      ).bind('active', now, currentUser.id, ip, signer_name, signer_role||'', nda_id).run();
    } catch(e) { return err('署名に失敗しました'); }
    // 申請元に通知
    try {
      await env.DB.prepare(
        'INSERT INTO notifications (id,user_id,module_id,type,title,body,action_url,is_read,created_at) VALUES (?,?,?,?,?,?,?,?,?)'
      ).bind('notif_'+Date.now().toString(36)+Math.random().toString(36).slice(2,4), nda.org_id_a,
        'medical-adapt','nda_signed',
        '【NDA締結完了】'+(currentUser.org||currentUser.login_id)+'がNDAに署名しました',
        '退院通知の送受信が可能になりました。',
        '#page:nda', 0, now).run();
    } catch(e) {}
    return json({ success: true, message: 'NDAに署名しました。退院通知の送受信が可能になりました。' });
  }

  // NDAテンプレート API
  // GET /nda/templates
  if (path === '/nda/templates' && method === 'GET') {
    const orgId = currentUser.org_id || currentUser.id;
    let templates = [];
    try {
      const r = await env.DB.prepare('SELECT * FROM nda_templates WHERE org_id=? ORDER BY updated_at DESC').bind(orgId).all();
      templates = r.results || [];
    } catch(e) {}
    return json({ templates });
  }

  // POST /nda/templates
  if (path === '/nda/templates' && method === 'POST') {
    const { name, form_type, content } = await request.json().catch(() => ({}));
    if (!name || !content) return err('テンプレート名と内容は必須です');
    const orgId = currentUser.org_id || currentUser.id;
    const id = 'tmpl_' + Date.now().toString(36) + Math.random().toString(36).slice(2,5);
    const now = new Date().toISOString();
    try {
      await env.DB.prepare(
        'INSERT INTO nda_templates (id,org_id,name,form_type,content,created_at,updated_at) VALUES (?,?,?,?,?,?,?)'
      ).bind(id, orgId, name, form_type||'bilateral', content, now, now).run();
    } catch(e) { return err('保存に失敗しました: '+e.message); }
    return json({ success: true, id, message: 'テンプレートを保存しました' });
  }

  // PUT /nda/templates/:id
  if (path.match(/^\/nda\/templates\/[^/]+$/) && method === 'PUT') {
    const tmplId = path.split('/').pop();
    const { name, form_type, content } = await request.json().catch(() => ({}));
    const orgId = currentUser.org_id || currentUser.id;
    const now = new Date().toISOString();
    try {
      await env.DB.prepare(
        'UPDATE nda_templates SET name=?,form_type=?,content=?,updated_at=? WHERE id=? AND org_id=?'
      ).bind(name, form_type||'bilateral', content, now, tmplId, orgId).run();
    } catch(e) { return err('更新に失敗しました'); }
    return json({ success: true, message: 'テンプレートを更新しました' });
  }

  // DELETE /nda/templates/:id
  if (path.match(/^\/nda\/templates\/[^/]+$/) && method === 'DELETE') {
    const tmplId = path.split('/').pop();
    const orgId = currentUser.org_id || currentUser.id;
    try {
      await env.DB.prepare('DELETE FROM nda_templates WHERE id=? AND org_id=?').bind(tmplId, orgId).run();
    } catch(e) { return err('削除に失敗しました'); }
    return json({ success: true, message: '削除しました' });
  }

  // DELETE /nda/:id （紙締結のみ・PW確認済み）
  if (path.match(/^\/nda\/[^/]+$/) && method === 'DELETE') {
    const ndaId = path.split('/')[2];
    const { password } = await request.json().catch(() => ({}));
    if (!password) return err('パスワードが必要です');
    const pwOk = currentUser.pw_hash
      ? await verifyPassword(password, currentUser.pw_hash)
      : (currentUser.pw === password);
    if (!pwOk) return err('パスワードが正しくありません');
    const orgId = currentUser.org_id || currentUser.id;
    let nda = null;
    try { nda = await env.DB.prepare('SELECT * FROM org_ndas WHERE id=?').bind(ndaId).first(); } catch(e) {}
    if (!nda) return err('NDAが見つかりません');
    if (nda.nda_type !== 'paper') return err('署名済みNDAは削除できません。終了処理を行ってください。');
    if (nda.org_id_a !== orgId && nda.org_id_b !== orgId) return err('削除権限がありません');
    try {
      await env.DB.prepare('DELETE FROM org_ndas WHERE id=?').bind(ndaId).run();
    } catch(e) { return err('削除に失敗しました'); }
    return json({ success: true, message: '紙締結NDAを削除しました' });
  }

  // POST /nda/:id/terminate （署名済みNDAの終了処理）
  if (path.match(/^\/nda\/[^/]+\/terminate$/) && method === 'POST') {
    const ndaId = path.split('/')[2];
    const { password } = await request.json().catch(() => ({}));
    if (!password) return err('パスワードが必要です');
    const pwOk = currentUser.pw_hash
      ? await verifyPassword(password, currentUser.pw_hash)
      : (currentUser.pw === password);
    if (!pwOk) return err('パスワードが正しくありません');
    const orgId = currentUser.org_id || currentUser.id;
    const now = new Date().toISOString();
    try {
      await env.DB.prepare('UPDATE org_ndas SET status=?,terminated_at=? WHERE id=? AND (org_id_a=? OR org_id_b=?)')
        .bind('terminated', now, ndaId, orgId, orgId).run();
    } catch(e) { return err('処理に失敗しました'); }
    return json({ success: true, message: 'NDAを終了処理しました' });
  }

  // POST /nda/:id/withdraw （申請取り下げ）
  if (path.match(/^\/nda\/[^/]+\/withdraw$/) && method === 'POST') {
    const ndaId = path.split('/')[2];
    const orgId = currentUser.org_id || currentUser.id;
    let nda = null;
    try { nda = await env.DB.prepare('SELECT * FROM org_ndas WHERE id=?').bind(ndaId).first(); } catch(e) {}
    if (!nda) return err('NDAが見つかりません');
    if (nda.org_id_a !== orgId) return err('申請者のみ取り下げできます');
    if (nda.status !== 'pending') return err('申請中のNDAのみ取り下げできます');
    try {
      await env.DB.prepare('DELETE FROM org_ndas WHERE id=?').bind(ndaId).run();
    } catch(e) { return err('取り下げに失敗しました'); }
    return json({ success: true, message: '申請を取り下げました' });
  }

  // ═══════════════════════════════════════════════
  // v9: 退院通知 API
  // ═══════════════════════════════════════════════

  // POST /discharge/new
  if (path === '/discharge/new' && method === 'POST') {
    const { patient_id, title, memo, pdf_url, pdf_filename, recipient_org_ids } = await request.json().catch(() => ({}));
    if (!patient_id || !title || !recipient_org_ids?.length) return err('患者・タイトル・通知先は必須です');
    const orgId = currentUser.org_id || currentUser.id;
    const id = 'dn_' + Date.now().toString(36) + Math.random().toString(36).slice(2,5);
    const now = new Date().toISOString();
    try {
      await env.DB.prepare(
        'INSERT INTO discharge_notices (id,patient_id,issued_by,org_id,title,memo,pdf_url,pdf_filename,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)'
      ).bind(id, patient_id, currentUser.id, orgId, title, memo||'', pdf_url||'', pdf_filename||'', 'active', now).run();
    } catch(e) { return err('退院通知の作成に失敗しました: '+e.message); }

    for (const recipientOrgId of recipient_org_ids) {
      // NDA確認
      let nda = null;
      try {
        nda = await env.DB.prepare(
          'SELECT id FROM org_ndas WHERE ((org_id_a=? AND org_id_b=?) OR (org_id_a=? AND org_id_b=?)) AND status=?'
        ).bind(orgId, recipientOrgId, recipientOrgId, orgId, 'active').first();
      } catch(e) {}
      if (!nda) continue;
      try {
        const recipId = 'nr_'+Date.now().toString(36)+Math.random().toString(36).slice(2,5);
        await env.DB.prepare(
          'INSERT OR IGNORE INTO notice_recipients (id,notice_id,recipient_org_id,access_stage,created_at) VALUES (?,?,?,?,?)'
        ).bind(recipId, id, recipientOrgId, 1, now).run();
      } catch(e) {}
      // 受信者の管理者に通知
      try {
        const adminUser = await env.DB.prepare(
          'SELECT id FROM users WHERE (org_id=? OR id=?) AND role=? LIMIT 1'
        ).bind(recipientOrgId, recipientOrgId, 'admin').first();
        if (adminUser) {
          await env.DB.prepare(
            'INSERT INTO notifications (id,user_id,module_id,type,title,body,action_url,is_read,created_at) VALUES (?,?,?,?,?,?,?,?,?)'
          ).bind('notif_'+Date.now().toString(36)+Math.random().toString(36).slice(2,4),
            adminUser.id, 'medical-adapt', 'discharge_notice',
            '【退院通知】'+title,
            memo||'退院通知が届いています。PDFを確認してください。',
            '#notice:'+id, 0, now).run();
        }
      } catch(e) {}
    }
    return json({ success: true, id, message: '退院通知を送信しました' });
  }

  // GET /discharge/list
  if (path === '/discharge/list' && method === 'GET') {
    const orgId = currentUser.org_id || currentUser.id;
    let sent = [], received = [];
    try {
      const s = await env.DB.prepare(
        'SELECT dn.id,dn.title,dn.memo,dn.status,dn.created_at,dn.pdf_filename,(SELECT COUNT(*) FROM notice_recipients nr WHERE nr.notice_id=dn.id) as recipient_count,(SELECT COUNT(*) FROM notice_recipients nr WHERE nr.notice_id=dn.id AND nr.joined_at IS NOT NULL) as joined_count FROM discharge_notices dn WHERE dn.org_id=? ORDER BY dn.created_at DESC LIMIT 20'
      ).bind(orgId).all();
      sent = s.results || [];
    } catch(e) {}
    try {
      const r = await env.DB.prepare(
        'SELECT dn.id,dn.title,dn.memo,dn.status,dn.created_at,dn.pdf_filename,nr.access_stage,nr.joined_at,nr.declined_at FROM notice_recipients nr JOIN discharge_notices dn ON nr.notice_id=dn.id WHERE nr.recipient_org_id=? ORDER BY dn.created_at DESC LIMIT 20'
      ).bind(orgId).all();
      received = r.results || [];
    } catch(e) {}
    return json({ sent, received });
  }

  // GET /discharge/:id
  if (path.match(/^\/discharge\/[^/]+$/) && method === 'GET') {
    const noticeId = path.split('/')[2];
    const orgId = currentUser.org_id || currentUser.id;
    let notice = null;
    try { notice = await env.DB.prepare('SELECT * FROM discharge_notices WHERE id=?').bind(noticeId).first(); } catch(e) {}
    if (!notice) return err('退院通知が見つかりません', 404);
    const isIssuer = notice.org_id === orgId;
    let recipient = null;
    if (!isIssuer) {
      try { recipient = await env.DB.prepare('SELECT * FROM notice_recipients WHERE notice_id=? AND recipient_org_id=?').bind(noticeId, orgId).first(); } catch(e) {}
      if (!recipient) return err('この退院通知へのアクセス権限がありません', 403);
    }
    const accessStage = isIssuer ? 99 : (recipient?.access_stage || 1);
    const data = {
      id: notice.id, title: notice.title, memo: notice.memo,
      status: notice.status, created_at: notice.created_at,
      access_stage: accessStage, is_issuer: isIssuer,
      pdf_url: notice.pdf_url, pdf_filename: notice.pdf_filename,
      joined_at: recipient?.joined_at || null,
      declined_at: recipient?.declined_at || null,
    };
    if (isIssuer) {
      try {
        const recs = await env.DB.prepare(
          'SELECT nr.recipient_org_id,nr.access_stage,nr.joined_at,nr.declined_at,u.org,u.login_id FROM notice_recipients nr LEFT JOIN users u ON (nr.recipient_org_id=u.org_id OR nr.recipient_org_id=u.id) WHERE nr.notice_id=? AND (u.role=? OR u.role IS NULL) GROUP BY nr.recipient_org_id'
        ).bind(noticeId, 'admin').all();
        data.recipients = recs.results || [];
      } catch(e) { data.recipients = []; }
    }
    return json(data);
  }

  // POST /discharge/:id/join
  if (path.match(/^\/discharge\/[^/]+\/join$/) && method === 'POST') {
    const noticeId = path.split('/')[2];
    const orgId = currentUser.org_id || currentUser.id;
    const now = new Date().toISOString();
    try {
      await env.DB.prepare(
        'UPDATE notice_recipients SET access_stage=2,joined_at=? WHERE notice_id=? AND recipient_org_id=? AND joined_at IS NULL'
      ).bind(now, noticeId, orgId).run();
    } catch(e) { return err('更新に失敗しました'); }
    try {
      const notice = await env.DB.prepare('SELECT * FROM discharge_notices WHERE id=?').bind(noticeId).first();
      if (notice) {
        await env.DB.prepare(
          'INSERT INTO notifications (id,user_id,module_id,type,title,body,action_url,is_read,created_at) VALUES (?,?,?,?,?,?,?,?,?)'
        ).bind('notif_'+Date.now().toString(36)+Math.random().toString(36).slice(2,4),
          notice.issued_by, 'medical-adapt', 'notice_joined',
          '【面談参加】'+(currentUser.org||currentUser.login_id)+'が面談への参加を表明しました',
          notice.title, '#notice:'+noticeId, 0, now).run();
      }
    } catch(e) {}
    return json({ success: true, message: '面談への参加を表明しました。日程調整をお待ちください。' });
  }

  // POST /discharge/:id/decline
  if (path.match(/^\/discharge\/[^/]+\/decline$/) && method === 'POST') {
    const noticeId = path.split('/')[2];
    const orgId = currentUser.org_id || currentUser.id;
    const now = new Date().toISOString();
    try {
      await env.DB.prepare(
        'UPDATE notice_recipients SET declined_at=? WHERE notice_id=? AND recipient_org_id=?'
      ).bind(now, noticeId, orgId).run();
    } catch(e) { return err('更新に失敗しました'); }
    return json({ success: true, message: '辞退しました' });
  }

  return err('Not found', 404);
}

// ── ログインID生成 ──────────────────────────────────────────
function genLoginId(prefix) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let id = prefix + '-';
  for (let i = 0; i < 6; i++) id += chars[Math.floor(Math.random() * chars.length)];
  return id;
}

// ── DB初期化 ──────────────────────────────────────────────
async function initDB(db) {
  const stmts = [
    `CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT, pw TEXT, pw_hash TEXT, org TEXT DEFAULT '', type TEXT DEFAULT '', name TEXT DEFAULT '', plan TEXT DEFAULT 'free', usage TEXT DEFAULT '{}', email_verified INTEGER DEFAULT 0, verify_token TEXT, reset_token TEXT, reset_expires TEXT, role TEXT DEFAULT 'admin', org_id TEXT, suspended INTEGER DEFAULT 0, qr_token TEXT, created TEXT)`,
    `CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, email TEXT NOT NULL, user_login_id TEXT, created TEXT, expires TEXT)`,
    `CREATE TABLE IF NOT EXISTS patients (id TEXT PRIMARY KEY, owner_email TEXT NOT NULL, data TEXT NOT NULL, created TEXT, updated TEXT)`,
    `CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, patient_id TEXT NOT NULL, owner_email TEXT NOT NULL, data TEXT NOT NULL, created TEXT, updated TEXT)`,
    `CREATE TABLE IF NOT EXISTS conferences (id TEXT PRIMARY KEY, patient_id TEXT, owner_email TEXT NOT NULL, data TEXT NOT NULL, created TEXT, updated TEXT)`,
    `CREATE TABLE IF NOT EXISTS monitors (id TEXT PRIMARY KEY, patient_id TEXT, owner_email TEXT NOT NULL, data TEXT NOT NULL, created TEXT, updated TEXT)`,
    `CREATE TABLE IF NOT EXISTS assessments (id TEXT PRIMARY KEY, patient_id TEXT NOT NULL, owner_email TEXT NOT NULL, data TEXT NOT NULL, created TEXT, updated TEXT)`,
    `CREATE TABLE IF NOT EXISTS documents (id TEXT PRIMARY KEY, patient_id TEXT NOT NULL, related_id TEXT DEFAULT '', owner_email TEXT NOT NULL, doc_type TEXT NOT NULL, title TEXT DEFAULT '', content TEXT NOT NULL, created_by TEXT DEFAULT '', created TEXT)`,
    `CREATE TABLE IF NOT EXISTS invites (id TEXT PRIMARY KEY, org_id TEXT NOT NULL, org_name TEXT DEFAULT '', email TEXT DEFAULT '', token TEXT NOT NULL, expires TEXT, used INTEGER DEFAULT 0, created TEXT)`,
    `CREATE INDEX IF NOT EXISTS idx_patients_owner ON patients(owner_email)`,
    `CREATE INDEX IF NOT EXISTS idx_documents_patient ON documents(patient_id)`,
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_users_login_id ON users(login_id)`,
    `CREATE TABLE IF NOT EXISTS org_ndas (id TEXT PRIMARY KEY, org_id_a TEXT NOT NULL, org_id_b TEXT NOT NULL, status TEXT DEFAULT 'pending', requested_at TEXT NOT NULL, signed_at TEXT, signed_by TEXT, signed_ip TEXT, terminated_at TEXT, UNIQUE(org_id_a, org_id_b))`,
    `CREATE TABLE IF NOT EXISTS discharge_notices (id TEXT PRIMARY KEY, patient_id TEXT NOT NULL, issued_by TEXT NOT NULL, org_id TEXT NOT NULL, title TEXT NOT NULL, memo TEXT DEFAULT '', pdf_url TEXT DEFAULT '', pdf_filename TEXT DEFAULT '', status TEXT DEFAULT 'active', created_at TEXT NOT NULL, closed_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS notice_recipients (id TEXT PRIMARY KEY, notice_id TEXT NOT NULL, recipient_org_id TEXT NOT NULL, access_stage INTEGER DEFAULT 1, joined_at TEXT, declined_at TEXT, proposal TEXT DEFAULT '{}', proposal_at TEXT, created_at TEXT NOT NULL, UNIQUE(notice_id, recipient_org_id))`,
    `CREATE TABLE IF NOT EXISTS schedule_polls (id TEXT PRIMARY KEY, notice_id TEXT NOT NULL, created_by TEXT NOT NULL, status TEXT DEFAULT 'open', confirmed_slot TEXT, call_url TEXT, deadline TEXT, created_at TEXT NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS schedule_slots (id TEXT PRIMARY KEY, poll_id TEXT NOT NULL, slot_datetime TEXT NOT NULL, label TEXT DEFAULT '')`,
    `CREATE TABLE IF NOT EXISTS schedule_votes (id TEXT PRIMARY KEY, slot_id TEXT NOT NULL, voter_org_id TEXT NOT NULL, voter_type TEXT DEFAULT '', answer TEXT NOT NULL, voted_at TEXT NOT NULL, UNIQUE(slot_id, voter_org_id))`,
    `CREATE TABLE IF NOT EXISTS match_selections (id TEXT PRIMARY KEY, notice_id TEXT NOT NULL, patient_id TEXT NOT NULL, selected_org_id TEXT NOT NULL, selected_at TEXT NOT NULL, note TEXT DEFAULT '')`,
  ];
  for (const sql of stmts) {
    try { await db.prepare(sql).run(); } catch (e) {
      if (!e.message?.includes('already exists')) console.error('initDB error:', e.message);
    }
  }
}

// ── パスワードハッシュ ────────────────────────────────────
async function hashPassword(password) {
  const salt = crypto.randomUUID().replace(/-/g, '');
  const enc = new TextEncoder();
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(password + salt));
  const hashHex = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `sha256:${salt}:${hashHex}`;
}

async function verifyPassword(password, stored) {
  if (!stored || !stored.startsWith('sha256:')) return false;
  const [, salt, hash] = stored.split(':');
  const enc = new TextEncoder();
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(password + salt));
  const hashHex = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex === hash;
}

// ── AWS SES メール送信 ────────────────────────────────────
async function sendEmail(env, { to, subject, html }) {
  const region = env.AWS_REGION || 'ap-northeast-1';
  const from = env.FROM_EMAIL || 'no-reply@tamjump.com';
  const accessKeyId = env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = env.AWS_SECRET_ACCESS_KEY;
  const endpoint = `https://email.${region}.amazonaws.com/v2/email/outbound-emails`;
  const body = JSON.stringify({
    FromEmailAddress: from,
    Destination: { ToAddresses: [to] },
    Content: { Simple: { Subject: { Data: subject, Charset: 'UTF-8' }, Body: { Html: { Data: html, Charset: 'UTF-8' } } } }
  });
  const now = new Date();
  const dateStr = now.toISOString().slice(0, 10).replace(/-/g, '');
  const timeStr = now.toISOString().replace(/[-:]/g, '').slice(0, 15) + 'Z';
  const service = 'ses';
  const enc = new TextEncoder();
  const sign = async (key, msg) => {
    const k = typeof key === 'string' ? enc.encode(key) : key;
    const ck = await crypto.subtle.importKey('raw', k, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', ck, enc.encode(msg)));
  };
  const hex = buf => Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
  const sha256 = async str => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(str))));
  const payloadHash = await sha256(body);
  const hdrs = { 'Content-Type': 'application/json', 'X-Amz-Date': timeStr, 'host': `email.${region}.amazonaws.com` };
  const signedHeaders = 'content-type;host;x-amz-date';
  const canonicalHeaders = `content-type:${hdrs['Content-Type']}\nhost:${hdrs['host']}\nx-amz-date:${timeStr}\n`;
  const canonicalRequest = `POST\n/v2/email/outbound-emails\n\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
  const credentialScope = `${dateStr}/${region}/${service}/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${timeStr}\n${credentialScope}\n${await sha256(canonicalRequest)}`;
  const kDate = await sign('AWS4' + secretAccessKey, dateStr);
  const kRegion = await sign(kDate, region);
  const kService = await sign(kRegion, service);
  const kSigning = await sign(kService, 'aws4_request');
  const signature = hex(await sign(kSigning, stringToSign));
  const authHeader = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  const res = await fetch(endpoint, { method: 'POST', headers: { ...hdrs, Authorization: authHeader }, body });
  if (!res.ok) { const text = await res.text(); console.error('SES error:', res.status, text); throw new Error(`SES送信エラー: ${res.status}`); }
  return res.json();
}

function safeJson(str) {
  try { return JSON.parse(str); } catch { return {}; }
}
