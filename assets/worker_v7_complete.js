// ｍやるゼ！ API Worker v7
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
      const baseUrl = 'https://myaruze.tamjump.com';
      const verifyUrl = `${baseUrl}/app.html?verify=${verifyToken}&login_id=${loginId}`;
      await sendEmail(env, {
        to: email.trim(),
        subject: '【ｍやるゼ！】メールアドレスの確認',
        html: `
          <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:24px;">
            <h2 style="color:#0891b2;">ｍやるゼ！へようこそ</h2>
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
            <p style="font-size:11px;color:#999;">タムジ.Corp | ｍやるゼ！ 医療介護連携OS</p>
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
    const baseUrl = 'https://myaruze.tamjump.com';
    const verifyUrl = `${baseUrl}/app.html?verify=${verifyToken}&email=${encodeURIComponent(email)}`;
    await sendEmail(env, {
      to: email,
      subject: '【ｍやるゼ！】メールアドレスの確認（再送）',
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
    // v22: 3値ステータス + access_blocked_at で判定
    const blockReason = checkUserAccessBlocked(user);
    if (blockReason) return err(blockReason, 403);

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
      const baseUrl = 'https://myaruze.tamjump.com';
      // login_id があればURLに含める（新しいリセット画面対応）
      const resetUrl = user.login_id
        ? `${baseUrl}/app.html?reset=${resetToken}&login_id=${user.login_id}`
        : `${baseUrl}/app.html?reset=${resetToken}&email=${encodeURIComponent(email)}`;
      await sendEmail(env, {
        to: email,
        subject: '【ｍやるゼ！】パスワードリセット',
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
      'INSERT INTO users (id,login_id,email,pw,pw_hash,org,type,name,plan,usage,email_verified,role,org_id,status,created) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
    ).bind(id, loginId, email||'', '', pwHash, adminUser.org, adminUser.type||'', name, 'staff', '{}', 1, 'staff', invite.org_id, 'active', now).run();

    await env.DB.prepare('UPDATE invites SET used=1 WHERE token=?').bind(invite_token).run();

    // v22: 翌月分課金人数を再計算（pending_member_count に反映）
    try { await recalcMemberCount(env, invite.org_id); } catch (e) { console.error('recalcMemberCount error:', e); }

    if (hasEmail) {
      try {
        await sendEmail(env, {
          to: email.trim(),
          subject: `【ｍやるゼ！】スタッフ登録完了 - あなたのログインID`,
          html: `
            <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:24px;">
              <h2 style="color:#0891b2;">スタッフ登録完了</h2>
              <p>${name} 様</p>
              <p>${adminUser.org} のｍやるゼ！への登録が完了しました。</p>
              <div style="background:#f0fdfa;border:1px solid #0891b2;border-radius:8px;padding:16px;margin:16px 0;text-align:center;">
                <div style="font-size:12px;color:#64748b;">あなたのログインIDは</div>
                <div style="font-size:28px;font-weight:900;color:#0891b2;letter-spacing:2px;">${loginId}</div>
              </div>
              <p style="font-size:12px;color:#666;">ログインURL: https://myaruze.tamjump.com/app.html</p>
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
    // v22: 3値ステータス + access_blocked_at で判定
    const qrBlockReason = checkUserAccessBlocked(user);
    if (qrBlockReason) return err(qrBlockReason, 403);
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

  // ── GET /billing/sdk-config（Web Payments SDK 用 public 値・認証不要）─
  if (path === '/billing/sdk-config' && method === 'GET') {
    const isSandbox = (env.SQUARE_API_BASE || '').includes('sandbox');
    return json({
      application_id: env.SQUARE_APP_ID || '',
      location_id: env.SQUARE_LOCATION_ID || '',
      environment: isSandbox ? 'sandbox' : 'production',
      sdk_url: isSandbox
        ? 'https://sandbox.web.squarecdn.com/v1/square.js'
        : 'https://web.squarecdn.com/v1/square.js',
    });
  }

  // ── POST /webhook/square（Square Webhook受信・認証不要・HMAC-SHA256検証）─
  if (path === '/webhook/square' && method === 'POST') {
    const rawBody = await request.text();
    const sig = request.headers.get('X-Square-HmacSha256-Signature')
             || request.headers.get('x-square-hmacsha256-signature')
             || '';
    const notificationUrl = request.url;
    const verifyResult = await verifySquareWebhookSignature(env, notificationUrl, rawBody, sig);
    if (!verifyResult.ok) {
      console.error('Square webhook signature verify failed:', verifyResult.reason);
      return err('署名検証失敗', 401);
    }
    let payload = {};
    try { payload = JSON.parse(rawBody); } catch { return err('JSON parse error', 400); }
    const eventType = payload?.type || payload?.event_type || '';
    const eventData = payload?.data?.object || {};
    const now = new Date().toISOString();
    try {
      if (eventType === 'invoice.payment_made') {
        const invoice = eventData?.invoice || {};
        const subscriptionId = invoice?.subscription_id;
        if (subscriptionId) {
          const yyyymm = now.slice(0, 7);
          await env.DB.prepare(
            'UPDATE subscriptions SET last_billed_month=? WHERE square_subscription_id=?'
          ).bind(yyyymm, subscriptionId).run();
          // 解約予約チェック：scheduled_cancel_month <= 当月 なら Square Cancel 実行
          const sub = await env.DB.prepare(
            'SELECT * FROM subscriptions WHERE square_subscription_id=?'
          ).bind(subscriptionId).first();
          let cancelled = false;
          if (sub && sub.scheduled_cancel_month && sub.scheduled_cancel_month <= yyyymm && sub.status === 'active') {
            try {
              await squareCancelSubscription(env, subscriptionId);
              await env.DB.prepare(
                "UPDATE subscriptions SET status='cancelled', cancelled_at=? WHERE square_subscription_id=?"
              ).bind(now, subscriptionId).run();
              console.log('Auto-cancelled by schedule:', subscriptionId, sub.scheduled_cancel_month);
              cancelled = true;
              // ★Phase 7: 親 adapt-api に解約同期（Webhook 経由・status='expired' / ended_at 設定）
              const adminLoginId = await getOrgAdminLoginId(env, sub.org_id);
              if (adminLoginId) {
                await syncToParent(env, adminLoginId, {
                  member_count: sub.member_count,
                  square_subscription_id: subscriptionId,
                  started_at: sub.started_at,
                  status: 'cancelled',  // syncToParent 内で 'expired' に正規化
                  ended_at: now,
                });
              } else {
                console.error('Phase 7 syncToParent skipped: admin login_id not found for org_id=', sub.org_id);
              }
            } catch (e) {
              console.error('Auto-cancel failed:', e);
            }
          }
          // v23.1: 翌月分の人数変更を反映（pending_member_changes 連動）
          if (sub && !cancelled && sub.org_id) {
            const nextMonth = addOneMonth(yyyymm);
            const pendingChange = await env.DB.prepare(
              'SELECT * FROM pending_member_changes WHERE org_id=? AND effective_month=?'
            ).bind(sub.org_id, nextMonth).first();
            if (pendingChange) {
              try {
                const retrieved = await squareRetrieveSubscription(env, subscriptionId);
                const version = retrieved?.subscription?.version;
                await squareUpdateSubscription(env, subscriptionId, pendingChange.member_count, version);
                await env.DB.prepare(
                  'UPDATE subscriptions SET member_count=?, amount_jpy=? WHERE square_subscription_id=?'
                ).bind(pendingChange.member_count, pendingChange.amount_jpy, subscriptionId).run();
                await env.DB.prepare(
                  'DELETE FROM pending_member_changes WHERE org_id=? AND effective_month=?'
                ).bind(sub.org_id, nextMonth).run();
                const nextPending = await env.DB.prepare(
                  'SELECT member_count FROM pending_member_changes WHERE org_id=? ORDER BY effective_month ASC LIMIT 1'
                ).bind(sub.org_id).first();
                await env.DB.prepare(
                  'UPDATE subscriptions SET pending_member_count=? WHERE square_subscription_id=?'
                ).bind(nextPending?.member_count ?? null, subscriptionId).run();
                console.log('Applied pending_member_change:', subscriptionId, nextMonth, pendingChange.member_count);
                // ★Phase 7: 親 adapt-api に人数同期（Webhook 経由・seat_count / unit_price 更新）
                const adminLoginId = await getOrgAdminLoginId(env, sub.org_id);
                if (adminLoginId) {
                  await syncToParent(env, adminLoginId, {
                    member_count: pendingChange.member_count,
                    square_subscription_id: subscriptionId,
                    started_at: sub.started_at,
                    status: 'active',
                    unit_price: 200,
                  });
                } else {
                  console.error('Phase 7 syncToParent skipped: admin login_id not found for org_id=', sub.org_id);
                }
              } catch (e) {
                console.error('Apply pending_member_change failed:', e);
              }
            }
          }
        }
      } else if (eventType === 'subscription.canceled' || eventType === 'subscription.cancelled') {
        const sub = eventData?.subscription || {};
        if (sub?.id) {
          await env.DB.prepare(
            "UPDATE subscriptions SET status='cancelled', cancelled_at=? WHERE square_subscription_id=?"
          ).bind(now, sub.id).run();
        }
      } else if (eventType === 'subscription.updated') {
        // 現状はログのみ（version不一致対策）
        console.log('subscription.updated received:', eventData?.subscription?.id);
      }
    } catch (e) {
      console.error('webhook handler error:', e);
    }
    return json({ ok: true });
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
    const baseUrl = 'https://myaruze.tamjump.com';
    const inviteUrl = `${baseUrl}/app.html?invite=${inviteToken}`;
    if (email) {
      await sendEmail(env, {
        to: email,
        subject: `【ｍやるゼ！】${currentUser.org}からスタッフ招待が届いています`,
        html: `
          <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:24px;">
            <h2 style="color:#0891b2;">ｍやるゼ！への招待</h2>
            <p>${currentUser.org} の管理者からｍやるゼ！への招待が届いています。</p>
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
      "SELECT id,login_id,email,name,role,plan,email_verified,suspended,status,access_blocked_at,created FROM users WHERE org_id=? AND role='staff' ORDER BY created ASC"
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
    const baseUrl = 'https://myaruze.tamjump.com';
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
    // v22: 3値モデルへ変換（後方互換維持）
    const newStatus = suspend ? 'suspended' : 'active';
    const now = new Date().toISOString();
    const blockedAt = suspend ? now : null;
    await env.DB.prepare('UPDATE users SET status=?, access_blocked_at=?, suspended=? WHERE id=?')
      .bind(newStatus, blockedAt, suspend ? 1 : 0, staff_id).run();
    if (suspend) await env.DB.prepare('DELETE FROM sessions WHERE email=?').bind(target.id).run();
    // 翌月分課金人数を再計算（pending_member_count に反映）
    await recalcMemberCount(env, orgId);
    return json({ success: true });
  }

  // ── v22: POST /staff/set-status（3値ステータス変更・最頻出エンドポイント）──
  // body: { staff_id, status: 'active'|'suspended'|'inactive', immediate?: boolean, block_until?: 'YYYY-MM-DD' }
  // inactive 時の優先順位: block_until > immediate > 当月末（grace・既定）
  if (path === '/staff/set-status' && method === 'POST') {
    if (currentUser.role !== 'admin') return err('管理者のみ実行できます', 403);
    const { staff_id, status: newStatus, immediate, block_until } = await request.json().catch(() => ({}));
    if (!staff_id) return err('staff_idが必要です');
    if (!['active', 'suspended', 'inactive'].includes(newStatus)) return err('statusはactive/suspended/inactiveのいずれかです');
    const orgId = currentUser.org_id || currentUser.id;
    const target = await env.DB.prepare('SELECT * FROM users WHERE id=? AND org_id=?').bind(staff_id, orgId).first();
    if (!target) return err('対象スタッフが見つかりません');
    const now = new Date().toISOString();
    let blockedAt = null;
    if (newStatus === 'suspended') {
      // 停止（休職）：即時ログイン不可
      blockedAt = now;
    } else if (newStatus === 'inactive') {
      // 削除（退職）：block_until > immediate > 当月末
      if (block_until) blockedAt = endOfDateIso(block_until);
      else if (immediate) blockedAt = now;
      else blockedAt = endOfCurrentMonthIso();
    } // 'active' は blockedAt=null
    // 旧 suspended カラムも互換維持（status='active' のときのみ 0）
    const legacySuspended = newStatus === 'active' ? 0 : 1;
    await env.DB.prepare('UPDATE users SET status=?, access_blocked_at=?, suspended=? WHERE id=?')
      .bind(newStatus, blockedAt, legacySuspended, staff_id).run();
    // 即時アクセス停止が発生する場合のみセッション破棄（block_until は未来日付なのでセッション維持）
    const isBlockedNow = blockedAt && new Date(blockedAt) <= new Date();
    if (newStatus === 'suspended' || (newStatus === 'inactive' && isBlockedNow)) {
      await env.DB.prepare('DELETE FROM sessions WHERE email=?').bind(target.id).run();
    }
    // 翌月分課金人数を再計算
    await recalcMemberCount(env, orgId);
    return json({ success: true, status: newStatus, access_blocked_at: blockedAt });
  }

  // ── DELETE /staff/:id ─────────────────────────────────────
  // v22: 物理削除を廃止。論理削除（status='inactive', immediate=true）に変更。
  // 履歴・参照整合性保護のため。物理削除したい場合は別途管理コマンドで対応。
  if (path.startsWith('/staff/') && method === 'DELETE') {
    if (currentUser.role !== 'admin') return err('管理者のみ実行できます', 403);
    const staffId = path.replace('/staff/', '');
    const orgId = currentUser.org_id || currentUser.id;
    const target = await env.DB.prepare('SELECT * FROM users WHERE id=? AND org_id=?').bind(staffId, orgId).first();
    if (!target) return err('対象スタッフが見つかりません');
    // 論理削除：status='inactive' + 即時アクセス停止
    const now = new Date().toISOString();
    await env.DB.prepare("UPDATE users SET status='inactive', access_blocked_at=?, suspended=1 WHERE id=?")
      .bind(now, staffId).run();
    await env.DB.prepare('DELETE FROM sessions WHERE email=?').bind(target.id).run();
    await recalcMemberCount(env, orgId);
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
      : 'ｍやるゼ！上でNDAに署名することで退院通知の送受信が可能になります。';
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
    const { patient_id, title, memo, pdf_data, pdf_filename, pdf_file_type, recipient_org_ids, requirements_data, schedule_slots } = await request.json().catch(() => ({}));
    if (!patient_id || !title || !recipient_org_ids?.length) return err('患者・タイトル・通知先は必須です');
    if (pdf_data && pdf_data.length > 4 * 1024 * 1024) return err('PDFは3MB以下にしてください');
    const orgId = currentUser.org_id || currentUser.id;
    const id = 'dn_' + Date.now().toString(36) + Math.random().toString(36).slice(2,5);
    const now = new Date().toISOString();
    try {
      await env.DB.prepare(
        'INSERT INTO discharge_notices (id,patient_id,issued_by,org_id,title,memo,pdf_url,pdf_filename,pdf_data,pdf_file_type,requirements_data,schedule_slots,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
      ).bind(id, patient_id, currentUser.id, orgId, title, memo||'', '', pdf_filename||'', pdf_data||'', pdf_file_type||'', requirements_data ? JSON.stringify(requirements_data) : '', schedule_slots ? JSON.stringify(schedule_slots) : '', 'active', now).run();
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
    const now = new Date().toISOString();
    // 7日以上無返答の受信者を自動で「返答なし」辞退
    try {
      const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
      await env.DB.prepare(
        "UPDATE notice_recipients SET declined_at=?,decline_reason='返答なし（自動）' WHERE declined_at IS NULL AND joined_at IS NULL AND recipient_org_id=? AND created_at<?"
      ).bind(now, orgId, sevenDaysAgo).run();
    } catch(e) {}
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
      has_pdf: !!(notice.pdf_data),
      meeting_url: notice.meeting_url || '',
      requirements_data: notice.requirements_data ? JSON.parse(notice.requirements_data) : null,
      schedule_slots: notice.schedule_slots ? JSON.parse(notice.schedule_slots) : [],
      confirmed_slot: notice.confirmed_slot || '',
      joined_at: recipient?.joined_at || null,
      declined_at: recipient?.declined_at || null,
      decline_reason: recipient?.decline_reason || '',
      proposal_data: recipient?.proposal_data ? JSON.parse(recipient.proposal_data) : null,
      schedule_votes: recipient?.schedule_votes ? JSON.parse(recipient.schedule_votes) : null,
    };
    if (isIssuer) {
      try {
        const recs = await env.DB.prepare(
          'SELECT nr.recipient_org_id,nr.access_stage,nr.joined_at,nr.declined_at,nr.decline_reason,nr.proposal_data,nr.schedule_votes,u.org,u.login_id FROM notice_recipients nr LEFT JOIN users u ON (nr.recipient_org_id=u.org_id OR nr.recipient_org_id=u.id) WHERE nr.notice_id=? AND (u.role=? OR u.role IS NULL) GROUP BY nr.recipient_org_id'
        ).bind(noticeId, 'admin').all();
        data.recipients = (recs.results || []).map(r => ({
          ...r,
          proposal_data: r.proposal_data ? JSON.parse(r.proposal_data) : null,
          schedule_votes: r.schedule_votes ? JSON.parse(r.schedule_votes) : null,
        }));
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
      const { proposal_data, schedule_votes } = await request.json().catch(() => ({}));
      await env.DB.prepare(
        'UPDATE notice_recipients SET access_stage=2,joined_at=?,proposal_data=?,schedule_votes=? WHERE notice_id=? AND recipient_org_id=? AND joined_at IS NULL'
      ).bind(now, proposal_data ? JSON.stringify(proposal_data) : '', schedule_votes ? JSON.stringify(schedule_votes) : '', noticeId, orgId).run();
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
    const { reason } = await request.json().catch(() => ({}));
    try {
      await env.DB.prepare(
        'UPDATE notice_recipients SET declined_at=?,decline_reason=? WHERE notice_id=? AND recipient_org_id=?'
      ).bind(now, reason||'', noticeId, orgId).run();
    } catch(e) { return err('更新に失敗しました'); }
    // 発行者に通知
    try {
      const notice = await env.DB.prepare('SELECT * FROM discharge_notices WHERE id=?').bind(noticeId).first();
      if (notice) {
        await env.DB.prepare(
          'INSERT INTO notifications (id,user_id,module_id,type,title,body,action_url,is_read,created_at) VALUES (?,?,?,?,?,?,?,?,?)'
        ).bind('notif_'+Date.now().toString(36)+Math.random().toString(36).slice(2,4),
          notice.issued_by, 'medical-adapt', 'discharge',
          '【辞退】'+(currentUser.org||currentUser.login_id)+'が辞退しました',
          reason ? '理由: '+reason : '理由の記載なし',
          '#notice:'+noticeId, 0, now).run();
      }
    } catch(e) {}
    return json({ success: true, message: '辞退しました' });
  }

  // GET /discharge/:id/pdf  — PDF取得（base64）
  if (path.match(/^\/discharge\/[^/]+\/pdf$/) && method === 'GET') {
    const noticeId = path.split('/')[2];
    const orgId = currentUser.org_id || currentUser.id;
    let notice = null;
    try { notice = await env.DB.prepare('SELECT org_id, pdf_data, pdf_file_type FROM discharge_notices WHERE id=?').bind(noticeId).first(); } catch(e) {}
    if (!notice?.pdf_data) return err('PDFが見つかりません', 404);
    // 発行者 or 受信者のみ取得可
    const isIssuer = notice.org_id === orgId;
    if (!isIssuer) {
      let rec = null;
      try { rec = await env.DB.prepare('SELECT id FROM notice_recipients WHERE notice_id=? AND recipient_org_id=? AND declined_at IS NULL').bind(noticeId, orgId).first(); } catch(e) {}
      if (!rec) return err('アクセス権限がありません', 403);
    }
    return json({ data: notice.pdf_data, file_type: notice.pdf_file_type || 'application/pdf' });
  }

  // POST /discharge/:id/meeting  — 発行者が面談URLを設定し、参加済み受信者をStage3へ
  if (path.match(/^\/discharge\/[^/]+\/meeting$/) && method === 'POST') {
    const noticeId = path.split('/')[2];
    const orgId = currentUser.org_id || currentUser.id;
    const { meeting_url } = await request.json().catch(() => ({}));
    if (!meeting_url) return err('面談URLを入力してください');
    // 発行者確認
    let notice = null;
    try { notice = await env.DB.prepare('SELECT * FROM discharge_notices WHERE id=?').bind(noticeId).first(); } catch(e) {}
    if (!notice) return err('退院通知が見つかりません', 404);
    if (notice.org_id !== orgId) return err('発行者のみ設定できます', 403);
    const now = new Date().toISOString();
    // meeting_urlを保存
    const { confirmed_slot } = await request.json().catch(() => ({}));
    try {
      await env.DB.prepare('UPDATE discharge_notices SET meeting_url=?,confirmed_slot=? WHERE id=?').bind(meeting_url, confirmed_slot||'', noticeId).run();
    } catch(e) { return err('更新に失敗しました: ' + e.message); }
    // 参加済み（access_stage=2）の受信者をStage3へ
    try {
      await env.DB.prepare(
        'UPDATE notice_recipients SET access_stage=3 WHERE notice_id=? AND access_stage=2'
      ).bind(noticeId).run();
    } catch(e) {}
    // 参加済み受信者に通知
    try {
      const joinedRecs = await env.DB.prepare(
        'SELECT nr.recipient_org_id FROM notice_recipients nr WHERE nr.notice_id=? AND nr.joined_at IS NOT NULL AND nr.declined_at IS NULL'
      ).bind(noticeId).all();
      for (const rec of (joinedRecs.results || [])) {
        const adminUser = await env.DB.prepare(
          'SELECT id FROM users WHERE (org_id=? OR id=?) AND role=? LIMIT 1'
        ).bind(rec.recipient_org_id, rec.recipient_org_id, 'admin').first().catch(() => null);
        if (adminUser) {
          await env.DB.prepare(
            'INSERT INTO notifications (id,user_id,module_id,type,title,body,action_url,is_read,created_at) VALUES (?,?,?,?,?,?,?,?,?)'
          ).bind('notif_'+Date.now().toString(36)+Math.random().toString(36).slice(2,4),
            adminUser.id, 'medical-adapt', 'discharge',
            '【面談URL確定】' + notice.title,
            '面談のURLが設定されました。確認してください。',
            '#notice:' + noticeId, 0, now).run();
        }
      }
    } catch(e) {}
    return json({ success: true, message: '面談URLを設定しました' });
  }

  // ────────────────────────────────────────────────────────
  // /billing/* — Square Subscriptions B-2方式（v8追加）
  // ────────────────────────────────────────────────────────

  // ── POST /billing/test/ping（Sandbox疎通確認）──
  if (path === '/billing/test/ping' && method === 'POST') {
    try {
      const data = await squareFetch(env, '/v2/locations', 'GET', null);
      const locations = data?.locations || [];
      const expected = env.SQUARE_LOCATION_ID || '';
      const match = locations.some(l => l.id === expected);
      const isSandbox = (env.SQUARE_API_BASE || '').includes('sandbox');
      return json({
        ok: true,
        env: isSandbox ? 'sandbox' : 'production',
        square_version: env.SQUARE_VERSION || null,
        expected_location_id: expected,
        location_match: match,
        location_count: locations.length,
      });
    } catch (e) {
      return err('Square API疎通失敗: ' + e.message, 500);
    }
  }

  // ── POST /billing/debug/apply-pending（admin限定・タスク2動作テスト用）──
  // invoice.payment_made を発火させずに、当月分の price_override 反映を手動実行
  // クエリ ?billing_month=YYYY-MM を指定すると、その月+1 の pending を反映（テスト用）
  // 未指定なら今日の月+1
  if (path === '/billing/debug/apply-pending' && method === 'POST') {
    if (currentUser.role !== 'admin') return err('代表者のみ操作できます', 403);
    const orgId = currentUser.org_id || currentUser.id;
    const moduleId = 'medical-adapt';
    const sub = await env.DB.prepare(
      'SELECT * FROM subscriptions WHERE org_id=? AND module_id=? AND status=?'
    ).bind(orgId, moduleId, 'active').first();
    if (!sub) return err('有効なサブスクリプションが見つかりません', 404);
    if (!sub.square_subscription_id) return err('Square Subscription ID 未設定', 400);
    // クエリで billing_month を受け取り（YYYY-MM 形式）。未指定なら今月。
    const billingMonth = url.searchParams.get('billing_month') || new Date().toISOString().slice(0, 7);
    if (!/^\d{4}-\d{2}$/.test(billingMonth)) return err('billing_month は YYYY-MM 形式で指定してください', 400);
    const nextMonth = addOneMonth(billingMonth);
    const pendingChange = await env.DB.prepare(
      'SELECT * FROM pending_member_changes WHERE org_id=? AND effective_month=?'
    ).bind(orgId, nextMonth).first();
    if (!pendingChange) {
      return json({ ok: true, applied: false, reason: 'no_pending_for_next_month', billing_month: billingMonth, next_month: nextMonth });
    }
    try {
      const retrieved = await squareRetrieveSubscription(env, sub.square_subscription_id);
      const version = retrieved?.subscription?.version;
      await squareUpdateSubscription(env, sub.square_subscription_id, pendingChange.member_count, version);
      await env.DB.prepare(
        'UPDATE subscriptions SET member_count=?, amount_jpy=? WHERE square_subscription_id=?'
      ).bind(pendingChange.member_count, pendingChange.amount_jpy, sub.square_subscription_id).run();
      await env.DB.prepare(
        'DELETE FROM pending_member_changes WHERE org_id=? AND effective_month=?'
      ).bind(orgId, nextMonth).run();
      const nextPending = await env.DB.prepare(
        'SELECT member_count FROM pending_member_changes WHERE org_id=? ORDER BY effective_month ASC LIMIT 1'
      ).bind(orgId).first();
      await env.DB.prepare(
        'UPDATE subscriptions SET pending_member_count=? WHERE square_subscription_id=?'
      ).bind(nextPending?.member_count ?? null, sub.square_subscription_id).run();
      // ★Phase 7: 親 adapt-api に人数同期（debug でも Webhook と同じく親同期する）
      // debug は admin user 自身が叩くので currentUser.login_id を使用
      await syncToParent(env, currentUser.login_id, {
        member_count: pendingChange.member_count,
        square_subscription_id: sub.square_subscription_id,
        started_at: sub.started_at,
        status: 'active',
        unit_price: 200,
      });
      return json({
        ok: true,
        applied: true,
        billing_month: billingMonth,
        applied_month: nextMonth,
        new_member_count: pendingChange.member_count,
        new_amount_jpy: pendingChange.amount_jpy,
        next_pending_member_count: nextPending?.member_count ?? null,
        square_version_before: version,
      });
    } catch (e) {
      return err('apply-pending failed: ' + e.message, 500);
    }
  }

  // ── POST /billing/reactivate（v28 Phase3: 解約済→再契約）──
  if (path === '/billing/reactivate' && method === 'POST') {
    if (currentUser.role !== 'admin') return err('代表者のみ操作できます', 403);
    const { card_source_id, verification_token } = await request.json().catch(() => ({}));
    if (!card_source_id) return err('card_source_id が必要です');

    const orgId = currentUser.org_id || currentUser.id;
    const moduleId = 'medical-adapt';
    const sub = await env.DB.prepare(
      'SELECT * FROM subscriptions WHERE org_id=? AND module_id=?'
    ).bind(orgId, moduleId).first();
    if (!sub) return err('再契約対象のサブスクが見つかりません', 404);
    if (sub.status !== 'cancelled') return err('解約済のサブスクのみ再契約できます', 409);

    let newCardId = null;
    try {
      // 1. Square Customer 確認/作成（cancelled でも通常は残っている）
      let squareCustomerId = sub.square_customer_id || currentUser.square_customer_id;
      if (!squareCustomerId) {
        const billEmail = sub.billing_email || currentUser.billing_email || currentUser.email || '';
        const custRes = await squareCreateCustomer(env, billEmail, currentUser.name);
        squareCustomerId = custRes?.customer?.id;
        if (!squareCustomerId) throw new Error('Customer取得/作成失敗');
        await env.DB.prepare(
          'UPDATE users SET square_customer_id=? WHERE id=?'
        ).bind(squareCustomerId, currentUser.id).run();
      }

      // 2. 新カード保存
      const cardRes = await squareCreateCard(env, squareCustomerId, card_source_id, verification_token);
      const cardObj = cardRes?.card || {};
      newCardId = cardObj.id;
      if (!newCardId) throw new Error('カード保存失敗');
      const newLast4 = cardObj.last_4 || null;
      const newBrand = cardObj.card_brand || null;
      const newExpMonth = cardObj.exp_month || null;
      const newExpYear = cardObj.exp_year || null;

      // 3. member_count 集計（v22: status='active' のみカウント）
      const cnt = await env.DB.prepare(
        "SELECT COUNT(*) as n FROM users WHERE org_id=? AND status='active'"
      ).bind(orgId).first();
      const memberCount = Math.max(1, cnt?.n || 1);
      const amountJpy = 200 * memberCount;

      // 4. 新 Subscription 作成
      const subRes = await squareCreateSubscription(env, squareCustomerId, newCardId, memberCount);
      const newSquareSubId = subRes?.subscription?.id;
      if (!newSquareSubId) throw new Error('Subscription再作成失敗');

      // 5. D1 UPDATE（status='active' 戻し + 新 sub_id + 新カード情報 + cancelled_at NULL）
      const now = new Date().toISOString();
      const previousSquareSubId = sub.square_subscription_id || null;
      await env.DB.prepare(
        `UPDATE subscriptions SET
           status='active', square_customer_id=?, square_subscription_id=?,
           started_at=?, cancelled_at=NULL, scheduled_cancel_month=NULL,
           member_count=?, amount_jpy=?,
           card_id=?, card_last_4=?, card_brand=?, card_exp_month=?, card_exp_year=?
         WHERE org_id=? AND module_id=?`
      ).bind(squareCustomerId, newSquareSubId, now, memberCount, amountJpy,
             newCardId, newLast4, newBrand, newExpMonth, newExpYear,
             orgId, moduleId).run();

      // 6. 親 adapt-api に同期
      await syncToParent(env, currentUser.login_id, {
        member_count: memberCount,
        square_subscription_id: newSquareSubId,
        started_at: now,
      });

      // 7. 課金履歴イベント記録（subscription_resumed）
      await recordBillingEvent(env, 'subscription_resumed', {
        member_count: memberCount,
        amount_jpy: amountJpy,
        square_subscription_id: newSquareSubId,
        previous_subscription_id: previousSquareSubId,
      }, currentUser);

      return json({
        success: true,
        subscription_id: newSquareSubId,
        amount_jpy: amountJpy,
        member_count: memberCount,
        card: { id: newCardId, last_4: newLast4, brand: newBrand, exp_month: newExpMonth, exp_year: newExpYear },
      });
    } catch (e) {
      console.error('billing/reactivate error:', e);
      if (newCardId) {
        try { await squareDisableCard(env, newCardId); } catch (_) {}
      }
      return err('再契約に失敗しました: ' + e.message, 500);
    }
  }

  // ── POST /billing/setup（初回サブスク作成）──
  if (path === '/billing/setup' && method === 'POST') {
    const { card_source_id, verification_token, billing_email } = await request.json().catch(() => ({}));
    if (!card_source_id) return err('card_source_id が必要です');
    if (currentUser.role !== 'admin') return err('代表者のみ操作できます', 403);

    const orgId = currentUser.org_id || currentUser.id;
    const billEmail = billing_email || currentUser.billing_email || currentUser.email || '';
    const moduleId = 'medical-adapt';

    // 既存サブスクの確認
    const existing = await env.DB.prepare(
      'SELECT * FROM subscriptions WHERE org_id=? AND module_id=?'
    ).bind(orgId, moduleId).first();
    if (existing && existing.square_subscription_id && existing.status === 'active') {
      return err('既に有効なサブスクリプションがあります', 409);
    }

    try {
      // 1. Square Customer 作成 or 既存使用
      let squareCustomerId = currentUser.square_customer_id;
      if (!squareCustomerId) {
        const custRes = await squareCreateCustomer(env, billEmail, currentUser.name);
        squareCustomerId = custRes?.customer?.id;
        if (!squareCustomerId) throw new Error('Customer作成失敗');
        await env.DB.prepare(
          'UPDATE users SET square_customer_id=?, billing_email=? WHERE id=?'
        ).bind(squareCustomerId, billEmail, currentUser.id).run();
      }

      // 2. カード保存
      const cardRes = await squareCreateCard(env, squareCustomerId, card_source_id, verification_token);
      const cardObj = cardRes?.card || {};
      const cardId = cardObj.id;
      if (!cardId) throw new Error('カード保存失敗');
      const cardLast4 = cardObj.last_4 || null;
      const cardBrand = cardObj.card_brand || null;
      const cardExpMonth = cardObj.exp_month || null;
      const cardExpYear = cardObj.exp_year || null;

      // 3. member_count 集計（v22: status='active' のみカウント）
      const cnt = await env.DB.prepare(
        "SELECT COUNT(*) as n FROM users WHERE org_id=? AND status='active'"
      ).bind(orgId).first();
      const memberCount = Math.max(1, cnt?.n || 1);
      const amountJpy = 200 * memberCount;

      // 4. CreateSubscription（price_override_money で動的金額）
      const subRes = await squareCreateSubscription(env, squareCustomerId, cardId, memberCount);
      const squareSubId = subRes?.subscription?.id;
      if (!squareSubId) throw new Error('Subscription作成失敗');

      // 5. D1更新（既存があればUPDATE、なければINSERT）
      const now = new Date().toISOString();
      if (existing) {
        await env.DB.prepare(
          `UPDATE subscriptions SET
             status='active', square_customer_id=?, square_subscription_id=?,
             member_count=?, amount_jpy=?, billing_email=?, started_at=?, cancelled_at=NULL,
             scheduled_cancel_month=NULL,
             card_id=?, card_last_4=?, card_brand=?, card_exp_month=?, card_exp_year=?
           WHERE org_id=? AND module_id=?`
        ).bind(squareCustomerId, squareSubId, memberCount, amountJpy, billEmail, now,
               cardId, cardLast4, cardBrand, cardExpMonth, cardExpYear,
               orgId, moduleId).run();
      } else {
        const newId = 'sub_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5);
        await env.DB.prepare(
          `INSERT INTO subscriptions
             (id, org_id, module_id, status, plan_type, started_at, auto_renew,
              square_customer_id, square_subscription_id, member_count, amount_jpy, billing_email, created_at,
              card_id, card_last_4, card_brand, card_exp_month, card_exp_year)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
        ).bind(newId, orgId, moduleId, 'active', 'monthly', now, 1,
               squareCustomerId, squareSubId, memberCount, amountJpy, billEmail, now,
               cardId, cardLast4, cardBrand, cardExpMonth, cardExpYear).run();
      }

      // 6. 親 adapt-api に同期（タスク3 / 設計書 v2 §22）
      // 失敗してもメイン処理は止めない（syncToParent 内で try/catch 済）
      await syncToParent(env, currentUser.login_id, {
        member_count: memberCount,
        square_subscription_id: squareSubId,
        started_at: now,
      });

      // 7. 課金履歴イベント記録（Phase 2.5）
      await recordBillingEvent(env, 'subscription_started', {
        member_count: memberCount,
        amount_jpy: amountJpy,
        square_subscription_id: squareSubId,
      }, currentUser);

      return json({
        success: true,
        subscription_id: squareSubId,
        amount_jpy: amountJpy,
        member_count: memberCount,
      });
    } catch (e) {
      console.error('billing/setup error:', e);
      return err('サブスク作成に失敗しました: ' + e.message, 500);
    }
  }

  // ── PUT /billing/update-members（人数変更を pending に記録・即課金変更しない）──
  if (path === '/billing/update-members' && method === 'PUT') {
    if (currentUser.role !== 'admin') return err('代表者のみ操作できます', 403);
    const orgId = currentUser.org_id || currentUser.id;
    const moduleId = 'medical-adapt';
    const sub = await env.DB.prepare(
      'SELECT * FROM subscriptions WHERE org_id=? AND module_id=?'
    ).bind(orgId, moduleId).first();
    if (!sub) return err('サブスクリプションが見つかりません', 404);
    const cnt = await env.DB.prepare(
      "SELECT COUNT(*) as n FROM users WHERE org_id=? AND status='active'"
    ).bind(orgId).first();
    const newCount = Math.max(1, cnt?.n || 1);
    if (newCount === sub.member_count) {
      // 変更なし → pending クリア
      await env.DB.prepare(
        'UPDATE subscriptions SET pending_member_count=NULL WHERE org_id=? AND module_id=?'
      ).bind(orgId, moduleId).run();
      return json({
        success: true,
        current_member_count: sub.member_count,
        pending_member_count: null,
        changed: false
      });
    }
    await env.DB.prepare(
      'UPDATE subscriptions SET pending_member_count=? WHERE org_id=? AND module_id=?'
    ).bind(newCount, orgId, moduleId).run();
    return json({
      success: true,
      current_member_count: sub.member_count,
      pending_member_count: newCount,
      changed: true,
      will_apply_at: '次回請求月'
    });
  }

  // ── DELETE /billing/cancel（即時解約・通常はwebhook経由でしか呼ばれない）──
  if (path === '/billing/cancel' && method === 'DELETE') {
    if (currentUser.role !== 'admin') return err('代表者のみ操作できます', 403);
    const orgId = currentUser.org_id || currentUser.id;
    const moduleId = 'medical-adapt';
    const sub = await env.DB.prepare(
      'SELECT * FROM subscriptions WHERE org_id=? AND module_id=?'
    ).bind(orgId, moduleId).first();
    if (!sub || !sub.square_subscription_id) return err('サブスクリプションが見つかりません', 404);
    if (sub.status === 'cancelled') return err('既に解約済みです', 409);
    try {
      await squareCancelSubscription(env, sub.square_subscription_id);
      const now = new Date().toISOString();
      await env.DB.prepare(
        "UPDATE subscriptions SET status='cancelled', cancelled_at=? WHERE org_id=? AND module_id=?"
      ).bind(now, orgId, moduleId).run();

      // Phase 2.5: 履歴記録
      await recordBillingEvent(env, 'cancelled', {
        cancelled_at: now,
        reason: 'manual',
        square_subscription_id: sub.square_subscription_id,
      }, currentUser);

      // ★Phase 7: 親 adapt-api に解約同期（status='expired' / ended_at 設定）
      // 失敗してもメイン処理は止めない（syncToParent 内で try/catch 済）
      await syncToParent(env, currentUser.login_id, {
        member_count: sub.member_count,
        square_subscription_id: sub.square_subscription_id,
        started_at: sub.started_at,
        status: 'cancelled',  // syncToParent 内で 'expired' に正規化
        ended_at: now,
      });

      return json({ success: true, cancelled_at: now });
    } catch (e) {
      console.error('billing/cancel error:', e);
      return err('解約処理に失敗しました: ' + e.message, 500);
    }
  }

  // ── POST /billing/schedule-cancel（解約予約・YYYY-MM指定）──
  if (path === '/billing/schedule-cancel' && method === 'POST') {
    if (currentUser.role !== 'admin') return err('代表者のみ操作できます', 403);
    const { month } = await request.json().catch(() => ({}));
    if (!month || !/^\d{4}-\d{2}$/.test(month)) return err('month は YYYY-MM 形式で指定してください');
    const orgId = currentUser.org_id || currentUser.id;
    const moduleId = 'medical-adapt';
    const sub = await env.DB.prepare(
      'SELECT * FROM subscriptions WHERE org_id=? AND module_id=?'
    ).bind(orgId, moduleId).first();
    if (!sub) return err('サブスクリプションが見つかりません', 404);
    if (sub.status !== 'active') return err('有効なサブスクリプションのみ予約できます', 409);
    // 過去月は受け付けない
    const nowMonth = new Date().toISOString().slice(0, 7);
    if (month < nowMonth) return err('過去の月は指定できません');
    await env.DB.prepare(
      'UPDATE subscriptions SET scheduled_cancel_month=? WHERE org_id=? AND module_id=?'
    ).bind(month, orgId, moduleId).run();

    // Phase 2.5: 履歴記録
    await recordBillingEvent(env, 'cancel_scheduled', {
      scheduled_cancel_month: month,
      prev_scheduled_cancel_month: sub.scheduled_cancel_month || null,
    }, currentUser);

    return json({ success: true, scheduled_cancel_month: month });
  }

  // ── POST /billing/unschedule-cancel（解約予約の取消）──
  if (path === '/billing/unschedule-cancel' && method === 'POST') {
    if (currentUser.role !== 'admin') return err('代表者のみ操作できます', 403);
    const orgId = currentUser.org_id || currentUser.id;
    const moduleId = 'medical-adapt';
    const sub = await env.DB.prepare(
      'SELECT scheduled_cancel_month FROM subscriptions WHERE org_id=? AND module_id=?'
    ).bind(orgId, moduleId).first();
    const prevMonth = sub?.scheduled_cancel_month || null;
    await env.DB.prepare(
      'UPDATE subscriptions SET scheduled_cancel_month=NULL WHERE org_id=? AND module_id=?'
    ).bind(orgId, moduleId).run();

    // Phase 2.5: 履歴記録
    await recordBillingEvent(env, 'unschedule_cancel', {
      prev_scheduled_cancel_month: prevMonth,
    }, currentUser);

    return json({ success: true });
  }

  // ── POST /billing/card/update（v26: カード変更・既存サブスクのカードを差し替え）──
  if (path === '/billing/card/update' && method === 'POST') {
    if (currentUser.role !== 'admin') return err('代表者のみ操作できます', 403);
    const { card_source_id, verification_token } = await request.json().catch(() => ({}));
    if (!card_source_id) return err('card_source_id が必要です');

    const orgId = currentUser.org_id || currentUser.id;
    const moduleId = 'medical-adapt';
    const sub = await env.DB.prepare(
      'SELECT * FROM subscriptions WHERE org_id=? AND module_id=?'
    ).bind(orgId, moduleId).first();
    if (!sub) return err('サブスクリプションが見つかりません', 404);
    if (sub.status !== 'active') return err('解約済み・停止中のサブスクではカード変更できません', 400);
    if (!sub.square_subscription_id) return err('Square サブスク ID がありません', 400);
    if (!sub.square_customer_id) return err('Square Customer ID がありません', 400);

    let newCardId = null;
    try {
      // 1. 新カード保存
      const cardRes = await squareCreateCard(env, sub.square_customer_id, card_source_id, verification_token);
      const cardObj = cardRes?.card || {};
      newCardId = cardObj.id;
      if (!newCardId) throw new Error('新カード保存失敗');
      const newLast4 = cardObj.last_4 || null;
      const newBrand = cardObj.card_brand || null;
      const newExpMonth = cardObj.exp_month || null;
      const newExpYear = cardObj.exp_year || null;

      // 2. subscription の version 取得
      const subRes = await squareRetrieveSubscription(env, sub.square_subscription_id);
      const version = subRes?.subscription?.version;
      if (version === undefined || version === null) throw new Error('subscription version 取得失敗');

      // 3. subscription のカードを切替
      await squareUpdateSubscriptionCard(env, sub.square_subscription_id, newCardId, version);

      // 4. 旧カード論理削除（失敗しても続行）
      const oldCardId = sub.card_id;
      if (oldCardId && oldCardId !== newCardId) {
        try { await squareDisableCard(env, oldCardId); } catch (e) {
          console.error('squareDisableCard (old) failed (ignored):', e?.message || e);
        }
      }

      // 5. D1 更新
      await env.DB.prepare(
        `UPDATE subscriptions SET
           card_id=?, card_last_4=?, card_brand=?, card_exp_month=?, card_exp_year=?
         WHERE org_id=? AND module_id=?`
      ).bind(newCardId, newLast4, newBrand, newExpMonth, newExpYear, orgId, moduleId).run();

      // 6. Phase 2.5: 履歴記録
      await recordBillingEvent(env, 'card_changed', {
        old_card: sub.card_id ? {
          card_id: sub.card_id,
          last_4: sub.card_last_4 || null,
          brand: sub.card_brand || null,
          exp_month: sub.card_exp_month || null,
          exp_year: sub.card_exp_year || null,
        } : null,
        new_card: {
          card_id: newCardId,
          last_4: newLast4,
          brand: newBrand,
          exp_month: newExpMonth,
          exp_year: newExpYear,
        },
      }, currentUser);

      return json({
        success: true,
        card: {
          id: newCardId,
          last_4: newLast4,
          brand: newBrand,
          exp_month: newExpMonth,
          exp_year: newExpYear,
        },
      });
    } catch (e) {
      console.error('billing/card/update error:', e);
      // ロールバック：新カードが作成済みなら disable
      if (newCardId) {
        try { await squareDisableCard(env, newCardId); } catch (_) {}
      }
      return err('カード変更に失敗しました: ' + e.message, 500);
    }
  }

  // ── GET /billing/info（マイページ用情報取得）──
  if (path === '/billing/info' && method === 'GET') {
    const orgId = currentUser.org_id || currentUser.id;
    const moduleId = 'medical-adapt';
    const sub = await env.DB.prepare(
      'SELECT * FROM subscriptions WHERE org_id=? AND module_id=?'
    ).bind(orgId, moduleId).first();
    if (!sub) {
      return json({
        has_subscription: false,
        has_card_on_file: !!currentUser.square_customer_id,
      });
    }
    // v23.1: 翌月以降の人数変更予定を時系列で取得
    const pendingRows = await env.DB.prepare(
      'SELECT effective_month, member_count, amount_jpy FROM pending_member_changes WHERE org_id=? ORDER BY effective_month ASC'
    ).bind(orgId).all();
    const pending_changes = (pendingRows?.results || []).map(r => ({
      effective_month: r.effective_month,
      member_count: r.member_count,
      amount_jpy: r.amount_jpy,
    }));
    // v26: カード情報取得（DB に無ければ Square API でバックフィル）
    const cardInfo = await ensureCardInfo(env, sub, orgId, moduleId);
    return json({
      has_subscription: true,
      status: sub.status,
      plan_type: sub.plan_type,
      member_count: sub.member_count || 1,
      pending_member_count: sub.pending_member_count,
      pending_changes,
      amount_jpy: sub.amount_jpy || 200,
      started_at: sub.started_at,
      cancelled_at: sub.cancelled_at,
      last_billed_month: sub.last_billed_month,
      scheduled_cancel_month: sub.scheduled_cancel_month,
      has_card_on_file: !!currentUser.square_customer_id,
      square_subscription_id: sub.square_subscription_id,
      card: cardInfo,
      can_reactivate: sub.status === 'cancelled' && !!currentUser.square_customer_id,
    });
  }

  // ── GET /billing/history（v27 Phase 2.5: 課金履歴取得・admin/staff 双方可）──
  if (path === '/billing/history' && method === 'GET') {
    const orgId = currentUser.org_id || currentUser.id;
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 200);
    const rows = await env.DB.prepare(
      "SELECT id, event_type, actor_login_id, actor_name, event_data, created_at " +
      "  FROM billing_events " +
      " WHERE org_id = ? " +
      " ORDER BY created_at DESC " +
      " LIMIT ?"
    ).bind(orgId, limit).all();
    const events = (rows?.results || []).map(r => {
      let parsed = null;
      try { parsed = r.event_data ? JSON.parse(r.event_data) : null; } catch (_) { parsed = null; }
      return {
        id: r.id,
        event_type: r.event_type,
        actor_login_id: r.actor_login_id,
        actor_name: r.actor_name,
        event_data: parsed,
        created_at: r.created_at,
      };
    });
    return json({ ok: true, events });
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
    `CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT, pw TEXT, pw_hash TEXT, org TEXT DEFAULT '', type TEXT DEFAULT '', name TEXT DEFAULT '', plan TEXT DEFAULT 'free', usage TEXT DEFAULT '{}', email_verified INTEGER DEFAULT 0, verify_token TEXT, reset_token TEXT, reset_expires TEXT, role TEXT DEFAULT 'admin', org_id TEXT, suspended INTEGER DEFAULT 0, status TEXT DEFAULT 'active', access_blocked_at TEXT, qr_token TEXT, created TEXT)`,
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

// ────────────────────────────────────────────────────────
// Square Subscriptions API ヘルパー（v8 / B-2方式）
// 1組織1サブスク・price_override_money で動的金額（200円 × member_count）
// ────────────────────────────────────────────────────────

function genUuid() {
  return (typeof crypto !== 'undefined' && crypto.randomUUID)
    ? crypto.randomUUID()
    : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
      });
}

async function squareFetch(env, path, method, body) {
  const base = env.SQUARE_API_BASE || 'https://connect.squareupsandbox.com';
  const version = env.SQUARE_VERSION || '2026-01-22';
  const token = env.SQUARE_ACCESS_TOKEN;
  if (!token) throw new Error('SQUARE_ACCESS_TOKEN 未設定');
  const res = await fetch(base + path, {
    method,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      'Square-Version': version,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  if (!res.ok) {
    const detail = data?.errors?.[0]?.detail || data?.errors?.[0]?.code || `HTTP ${res.status}`;
    const e = new Error(`Square API error: ${detail}`);
    e.squareStatus = res.status;
    e.squareBody = data;
    throw e;
  }
  return data;
}

async function squareCreateCustomer(env, email, name) {
  return squareFetch(env, '/v2/customers', 'POST', {
    idempotency_key: genUuid(),
    email_address: email || undefined,
    given_name: name || undefined,
  });
}

async function squareCreateCard(env, customerId, sourceId, verificationToken) {
  // sourceId: Web Payments SDK tokenize() 戻り値の token、Sandbox 用は 'cnon:card-nonce-ok'
  return squareFetch(env, '/v2/cards', 'POST', {
    idempotency_key: genUuid(),
    source_id: sourceId,
    verification_token: verificationToken || undefined,
    card: { customer_id: customerId },
  });
}

async function squareCreateSubscription(env, customerId, cardId, memberCount) {
  const amount = 200 * Math.max(1, memberCount || 1);
  return squareFetch(env, '/v2/subscriptions', 'POST', {
    idempotency_key: genUuid(),
    location_id: env.SQUARE_LOCATION_ID,
    plan_variation_id: env.SQUARE_PLAN_VARIATION_ID,
    customer_id: customerId,
    card_id: cardId,
    price_override_money: { amount, currency: 'JPY' },
    timezone: 'Asia/Tokyo',
    source: { name: 'やるゼ！' },
  });
}

async function squareRetrieveSubscription(env, subscriptionId) {
  return squareFetch(env, '/v2/subscriptions/' + encodeURIComponent(subscriptionId), 'GET', null);
}

async function squareUpdateSubscription(env, subscriptionId, memberCount, version) {
  const amount = 200 * Math.max(1, memberCount || 1);
  return squareFetch(env, '/v2/subscriptions/' + encodeURIComponent(subscriptionId), 'PUT', {
    subscription: {
      price_override_money: { amount, currency: 'JPY' },
      version: version,
    },
  });
}

async function squareCancelSubscription(env, subscriptionId) {
  return squareFetch(env, '/v2/subscriptions/' + encodeURIComponent(subscriptionId) + '/cancel', 'POST', {});
}

// v26: subscription のカードを変更（PUT /v2/subscriptions/:id with card_id）
async function squareUpdateSubscriptionCard(env, subscriptionId, cardId, version) {
  return squareFetch(env, '/v2/subscriptions/' + encodeURIComponent(subscriptionId), 'PUT', {
    subscription: {
      card_id: cardId,
      version: version,
    },
  });
}

// v26: カード論理削除（POST /v2/cards/:id/disable）
async function squareDisableCard(env, cardId) {
  return squareFetch(env, '/v2/cards/' + encodeURIComponent(cardId) + '/disable', 'POST', {});
}

// v26: カード詳細取得（GET /v2/cards/:id）
async function squareGetCard(env, cardId) {
  return squareFetch(env, '/v2/cards/' + encodeURIComponent(cardId), 'GET', null);
}

// v26: カード情報取得＋バックフィル
// 1. D1 にカード詳細があればそれを返す
// 2. card_id が D1 にあれば Square API で取得 → D1 にバックフィル
// 3. card_id すら無い既存サブスクは subscription から card_id 取得 → 同上
async function ensureCardInfo(env, sub, orgId, moduleId) {
  if (!sub) return null;
  if (sub.card_last_4) {
    return {
      id: sub.card_id || null,
      last_4: sub.card_last_4,
      brand: sub.card_brand || null,
      exp_month: sub.card_exp_month || null,
      exp_year: sub.card_exp_year || null,
    };
  }
  let cardId = sub.card_id || null;
  if (!cardId && sub.square_subscription_id) {
    try {
      const subRes = await squareRetrieveSubscription(env, sub.square_subscription_id);
      cardId = subRes?.subscription?.card_id || null;
    } catch (e) {
      console.error('ensureCardInfo squareRetrieveSubscription failed:', e?.message || e);
    }
  }
  if (!cardId) return null;
  try {
    const cardRes = await squareGetCard(env, cardId);
    const c = cardRes?.card || {};
    if (!c.id) return null;
    const info = {
      id: c.id,
      last_4: c.last_4 || null,
      brand: c.card_brand || null,
      exp_month: c.exp_month || null,
      exp_year: c.exp_year || null,
    };
    try {
      await env.DB.prepare(
        'UPDATE subscriptions SET card_id=?, card_last_4=?, card_brand=?, card_exp_month=?, card_exp_year=? WHERE org_id=? AND module_id=?'
      ).bind(info.id, info.last_4, info.brand, info.exp_month, info.exp_year, orgId, moduleId).run();
    } catch (e) {
      console.error('ensureCardInfo backfill failed:', e?.message || e);
    }
    return info;
  } catch (e) {
    console.error('ensureCardInfo squareGetCard failed:', e?.message || e);
    return null;
  }
}

// ============================================================
// タスク3: 子→親 subscription 同期パイプ（設計書 v2 §22 / 引継書 v25 §5-5）
// ============================================================
// 親 adapt-api に Service Binding ADAPT_SVC 経由で同期する（同一Cloudflareアカウント間
// の通常 fetch は Error 1042 で遮断されるため Service Binding 必須）
// ADAPT_SVC 未設定時は通常 fetch にフォールバック（外部Workerから呼ばれた場合の保険）
// 失敗してもメイン処理（子側の課金成立）は影響を受けない（try/catch で完結）
async function syncToParent(env, loginId, subData) {
  try {
    if (!env.INTERNAL_API_KEY) {
      console.error('syncToParent: INTERNAL_API_KEY not set');
      return;
    }
    const authHeader = 'Bearer ' + env.INTERNAL_API_KEY;

    const adaptFetch = (path, init) => {
      if (env.ADAPT_SVC) {
        return env.ADAPT_SVC.fetch('https://internal' + path, init);
      }
      return fetch('https://adapt-api.animalb001.workers.dev' + path, init);
    };

    // STEP 1: child_login_id から master_company_id を逆引き
    const lookupRes = await adaptFetch(
      '/api/internal/master-company-by-child-login' +
      '?app_name=medadapt&child_login_id=' + encodeURIComponent(loginId),
      { headers: { 'Authorization': authHeader } }
    );
    const lookup = await lookupRes.json();
    if (!lookup.ok) {
      console.error('syncToParent lookup failed:', lookup);
      return;
    }
    if (!lookup.master_company_id) {
      console.log('syncToParent: not_linked, skip', { loginId, reason: lookup.reason });
      return;
    }

    // STEP 2: 親に subscription-sync を投げる
    // ★Phase 7：subData.status / subData.ended_at / subData.unit_price を optional 受付
    // 子の status='cancelled' は親では 'expired' に正規化（adapt-db の status 体系に合わせる）
    const rawStatus = subData.status || 'active';
    const normalizedStatus = (rawStatus === 'cancelled') ? 'expired' : rawStatus;
    const syncRes = await adaptFetch(
      '/api/internal/subscription-sync',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': authHeader,
        },
        body: JSON.stringify({
          master_company_id: lookup.master_company_id,
          app_name: 'medadapt',
          plan: 'pro',
          seat_count: subData.member_count,
          unit_price: subData.unit_price ?? 200,
          square_subscription_id: subData.square_subscription_id,
          started_at: subData.started_at,
          status: normalizedStatus,
          ended_at: subData.ended_at ?? null,
        }),
      }
    );
    const syncResult = await syncRes.json();
    console.log('syncToParent result:', syncResult);
  } catch (e) {
    console.error('syncToParent error (non-fatal):', e);
  }
}

// ============================================================
// Phase 7: org_id から代表者の login_id を引き当てるヘルパー
// ============================================================
// Webhook は authenticated user を持たないため、Webhook 内で syncToParent を
// 呼ぶ際に loginId を子 DB から動的引き当てする。
// users.role='admin' で status='active' のユーザーのうち、最古に作成された 1 件を採用。
// （複数 admin が存在する場合に備える）
async function getOrgAdminLoginId(env, orgId) {
  if (!orgId) return null;
  try {
    const admin = await env.DB.prepare(
      "SELECT login_id FROM users WHERE org_id=? AND role='admin' AND status='active' ORDER BY created ASC LIMIT 1"
    ).bind(orgId).first();
    return admin?.login_id || null;
  } catch (e) {
    console.error('getOrgAdminLoginId error:', e);
    return null;
  }
}

// ============================================================
// Phase 2.5: 課金履歴 billing_events 記録ヘルパー（設計書 v4 §24 予定）
// ============================================================
// ローカル DB の billing_events に INSERT し、続けて親 adapt-api の
// /api/internal/billing-event-sync を Service Binding 経由で叩いて同期する。
// ローカル INSERT が失敗した場合は親同期もスキップする。
// 親同期失敗時はメイン処理に影響を与えない（呼び出し側の課金成立は止めない）。
async function recordBillingEvent(env, eventType, eventData, currentUser) {
  const orgId = currentUser?.org_id || currentUser?.id || null;
  const eventId = 'BE-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  const now = new Date().toISOString();

  // 1. ローカル DB に記録
  try {
    await env.DB.prepare(
      "INSERT INTO billing_events " +
      "  (id, org_id, company_code, event_type, actor_login_id, actor_name, event_data, created_at) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(
      eventId,
      orgId,
      null,
      eventType,
      currentUser?.login_id || null,
      currentUser?.name || null,
      JSON.stringify(eventData || {}),
      now
    ).run();
  } catch (e) {
    console.error('recordBillingEvent local insert failed:', e);
    return;
  }

  // 2. 親 adapt-api に同期（失敗してもメイン処理は止めない）
  try {
    if (!env.INTERNAL_API_KEY) {
      console.log('recordBillingEvent: INTERNAL_API_KEY not set, skip parent sync');
      return;
    }
    if (!currentUser?.login_id) {
      console.log('recordBillingEvent: no login_id, skip parent sync');
      return;
    }
    const adaptFetch = (path, init) => {
      if (env.ADAPT_SVC) {
        return env.ADAPT_SVC.fetch('https://internal' + path, init);
      }
      return fetch('https://adapt-api.animalb001.workers.dev' + path, init);
    };
    const syncRes = await adaptFetch(
      '/api/internal/billing-event-sync',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + env.INTERNAL_API_KEY,
        },
        body: JSON.stringify({
          app_name: 'medadapt',
          child_login_id: currentUser.login_id,
          event_type: eventType,
          actor_login_id: currentUser.login_id,
          actor_name: currentUser.name || null,
          event_data: eventData || {},
          occurred_at: now,
        }),
      }
    );
    const result = await syncRes.json();
    console.log('recordBillingEvent sync result:', result);
  } catch (e) {
    console.error('recordBillingEvent parent sync error (non-fatal):', e);
  }
}

// ============================================================
// v22: 3値ステータス（active/suspended/inactive）+ access_blocked_at 関連ヘルパー
// ============================================================

// ログイン拒否判定。null 返却なら通過、文字列返却ならその理由でログイン拒否。
function checkUserAccessBlocked(user, now = new Date()) {
  // 後方互換：status カラムが NULL の古いレコードは suspended カラムを参照
  const status = user.status || (user.suspended ? 'suspended' : 'active');
  if (status === 'active') return null;
  if (status === 'suspended') return 'このアカウントは停止中です。管理者にお問い合わせください。';
  if (status === 'inactive') {
    // 「決済済み月末まで利用可能」を尊重する判定
    if (user.access_blocked_at) {
      const blockedAt = new Date(user.access_blocked_at);
      if (now >= blockedAt) return 'このアカウントは利用終了しています。';
      return null; // 期限まではアクセス可
    }
    return 'このアカウントは利用終了しています。';
  }
  return null;
}

// 当月末 23:59:59.999 (JST) の ISO 8601 文字列を返す
// JST固定で当月末を計算（タイムゾーン依存を排除）
function endOfCurrentMonthIso(now = new Date()) {
  const jst = new Date(now.getTime() + 9 * 60 * 60 * 1000);
  const y = jst.getUTCFullYear();
  const m = jst.getUTCMonth(); // 0-11
  // 翌月1日 00:00:00 JST = 当月末 24:00:00 JST = UTC で前日 15:00
  const nextMonthFirstUtc = Date.UTC(y, m + 1, 1, 0, 0, 0) - 9 * 60 * 60 * 1000;
  // 当月末 23:59:59.999 JST = 翌月1日 0:00 JST の 1ms 前
  return new Date(nextMonthFirstUtc - 1).toISOString();
}

// 'YYYY-MM-DD' を JST のその日 23:59:59.999 の ISO 8601 文字列に変換
// 例: '2026-08-15' → JST 2026-08-15 23:59:59.999 = UTC 2026-08-15 14:59:59.999Z
function endOfDateIso(dateStr) {
  if (!dateStr || !/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return null;
  const [y, m, d] = dateStr.split('-').map(Number);
  // 翌日 0:00 JST = UTC 前日 15:00 → -1ms で当日 23:59:59.999 JST
  const nextDayFirstUtc = Date.UTC(y, m - 1, d + 1, 0, 0, 0) - 9 * 60 * 60 * 1000;
  return new Date(nextDayFirstUtc - 1).toISOString();
}

// 月文字列 'YYYY-MM' に 1ヶ月加算
function addOneMonth(yyyymm) {
  const [y, m] = yyyymm.split('-').map(Number);
  return m === 12 ? `${y + 1}-01` : `${y}-${String(m + 1).padStart(2, '0')}`;
}

// メンバー数を再計算して subscriptions と pending_member_changes に反映（v23.1 ロジック）
// - active ユーザー数 + 未来日 access_blocked_at を持つ inactive ユーザー数 = 現在の課金対象
// - 月別に外れる人数を集計し pending_member_changes を時系列再生成
async function recalcMemberCount(env, orgId) {
  if (!orgId) return;
  try {
    const moduleId = 'medical-adapt';
    const sub = await env.DB.prepare(
      'SELECT id, member_count FROM subscriptions WHERE org_id=? AND module_id=? AND status=?'
    ).bind(orgId, moduleId, 'active').first();
    if (!sub) return; // サブスク未契約 or 非active なら何もしない（既存挙動維持）

    const nowIso = new Date().toISOString();

    // 1) active ユーザー数
    const activeRow = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM users WHERE org_id=? AND status='active'"
    ).bind(orgId).first();
    const N_active = activeRow?.n || 0;

    // 2) inactive かつ access_blocked_at が未来（＝当月以降に課金対象から外れる予定）
    const blockRows = await env.DB.prepare(
      "SELECT id, access_blocked_at FROM users WHERE org_id=? AND status='inactive' AND access_blocked_at IS NOT NULL AND access_blocked_at > ?"
    ).bind(orgId, nowIso).all();
    const block_users = blockRows?.results || [];

    // 3) 現在の課金対象人数（Square API は最低1名要求のため floor 1 で安全側に）
    const now_count = Math.max(1, N_active + block_users.length);

    // 4) 月別に外れる人数を集計（access_blocked_at 月の翌月から減算）
    const monthlyDecrements = {};
    for (const u of block_users) {
      if (!u.access_blocked_at) continue;
      const blockMonth = u.access_blocked_at.slice(0, 7); // 'YYYY-MM'
      const nextMonth = addOneMonth(blockMonth);
      monthlyDecrements[nextMonth] = (monthlyDecrements[nextMonth] || 0) + 1;
    }

    // 5) pending_member_changes を org 単位で全消し→時系列再生成
    await env.DB.prepare(
      'DELETE FROM pending_member_changes WHERE org_id=?'
    ).bind(orgId).run();

    const months = Object.keys(monthlyDecrements).sort();
    let runningCount = now_count;
    let earliestPendingCount = null;
    for (const m of months) {
      runningCount -= monthlyDecrements[m];
      const amount = 200 * runningCount;
      await env.DB.prepare(
        'INSERT INTO pending_member_changes (org_id, effective_month, member_count, amount_jpy, source_user_id, created_at) VALUES (?, ?, ?, ?, NULL, ?)'
      ).bind(orgId, m, runningCount, amount, nowIso).run();
      if (earliestPendingCount === null) earliestPendingCount = runningCount;
    }

    // 6) subscriptions の代表値を更新
    await env.DB.prepare(
      'UPDATE subscriptions SET member_count=?, amount_jpy=?, pending_member_count=? WHERE id=?'
    ).bind(now_count, 200 * now_count, earliestPendingCount, sub.id).run();

  } catch (e) {
    console.error('recalcMemberCount error:', e);
  }
}

// Square Webhook 署名検証
// Squareは notification_url + raw_body を WEBHOOK_SIGNATURE_KEY で HMAC-SHA256 → Base64 して送る
async function verifySquareWebhookSignature(env, notificationUrl, rawBody, signatureHeader) {
  const key = env.SQUARE_WEBHOOK_SIGNATURE_KEY;
  if (!key) return { ok: false, reason: 'no_key' };
  if (!signatureHeader) return { ok: false, reason: 'no_signature' };
  const enc = new TextEncoder();
  const ck = await crypto.subtle.importKey(
    'raw', enc.encode(key),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sigBuf = await crypto.subtle.sign('HMAC', ck, enc.encode(notificationUrl + rawBody));
  const expected = btoa(String.fromCharCode(...new Uint8Array(sigBuf)));
  // timing-safe compare
  if (expected.length !== signatureHeader.length) return { ok: false, reason: 'length_mismatch' };
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ signatureHeader.charCodeAt(i);
  }
  return { ok: diff === 0, reason: diff === 0 ? null : 'mismatch' };
}
