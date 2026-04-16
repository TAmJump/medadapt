// =============================================================
// Worker v8 追加コード
// Cloudflare Workers & Pages → medadapt-api-v2 → Edit code
// 既存のWorkerコードの「// ルーティング」部分の先頭付近に追加する
// =============================================================

// ─────────────────────────────────────────────
// GET /modules/:moduleId/access
// モジュール利用権チェック
// ─────────────────────────────────────────────
if (method === 'GET' && path.startsWith('/modules/') && path.endsWith('/access')) {
  const moduleId = path.split('/')[2]; // 例: 'medical-adapt'
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) return json({ error: '認証が必要です' }, 401);

  // セッション確認
  const session = await env.DB.prepare(
    'SELECT * FROM sessions WHERE token=? AND expires>?'
  ).bind(token, new Date().toISOString()).first();
  if (!session) return json({ error: 'セッションが無効です' }, 401);

  const user = await env.DB.prepare(
    'SELECT * FROM users WHERE id=?'
  ).bind(session.email).first(); // sessions.emailにはuser.idが入っている
  if (!user) return json({ error: 'ユーザーが見つかりません' }, 404);

  // subscriptionsテーブルを確認
  const sub = await env.DB.prepare(
    'SELECT * FROM subscriptions WHERE org_id=? AND module_id=? AND cancelled_at IS NULL'
  ).bind(user.org_id || user.id, moduleId).first();

  // subscriptionsが未作成（既存ユーザー）の場合はplanカラムで判定
  if (!sub) {
    // 後方互換: usersテーブルのplanが'pro'または'staff'なら許可
    if (user.plan === 'pro' || user.plan === 'staff' || user.role === 'staff') {
      return json({ access: true, status: 'active', compat: true });
    }
    // Freeプランでも基本アクセスは許可（Free制限はfreeCheck関数が担当）
    return json({ access: true, status: 'free', compat: true });
  }

  const now = new Date().toISOString();

  // 無料期間中
  if (sub.trial_end_at && sub.trial_end_at > now) {
    return json({
      access: true,
      status: 'trial',
      trial_end_at: sub.trial_end_at,
      free_months_remaining: sub.free_months_remaining || 0
    });
  }

  // 課金中
  if (sub.status === 'active') {
    return json({ access: true, status: 'active' });
  }

  // 停止中（未払い）
  if (sub.status === 'suspended') {
    return json({ access: false, reason: 'payment_failed', status: 'suspended' });
  }

  // 解約済み
  if (sub.status === 'cancelled') {
    return json({ access: false, reason: 'cancelled', status: 'cancelled' });
  }

  return json({ access: true, status: sub.status });
}

// ─────────────────────────────────────────────
// GET /notifications/unread
// 未読通知数を返す
// ─────────────────────────────────────────────
if (method === 'GET' && path === '/notifications/unread') {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) return json({ count: 0 });

  const session = await env.DB.prepare(
    'SELECT * FROM sessions WHERE token=? AND expires>?'
  ).bind(token, new Date().toISOString()).first();
  if (!session) return json({ count: 0 });

  const user = await env.DB.prepare(
    'SELECT * FROM users WHERE id=?'
  ).bind(session.email).first();
  if (!user) return json({ count: 0 });

  const result = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM notifications WHERE user_id=? AND is_read=0'
  ).bind(user.id).first();

  return json({ count: result?.count || 0 });
}

// ─────────────────────────────────────────────
// GET /notifications
// 通知一覧（最新30件）
// ─────────────────────────────────────────────
if (method === 'GET' && path === '/notifications') {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) return json({ error: '認証が必要です' }, 401);

  const session = await env.DB.prepare(
    'SELECT * FROM sessions WHERE token=? AND expires>?'
  ).bind(token, new Date().toISOString()).first();
  if (!session) return json({ error: 'セッション無効' }, 401);

  const user = await env.DB.prepare(
    'SELECT * FROM users WHERE id=?'
  ).bind(session.email).first();

  const notifs = await env.DB.prepare(
    'SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 30'
  ).bind(user.id).all();

  return json({ notifications: notifs.results || [] });
}

// ─────────────────────────────────────────────
// POST /notifications/:id/read
// 通知を既読にする
// ─────────────────────────────────────────────
if (method === 'POST' && path.match(/^\/notifications\/[^/]+\/read$/)) {
  const notifId = path.split('/')[2];
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) return json({ error: '認証が必要です' }, 401);

  const session = await env.DB.prepare(
    'SELECT * FROM sessions WHERE token=? AND expires>?'
  ).bind(token, new Date().toISOString()).first();
  if (!session) return json({ error: 'セッション無効' }, 401);

  const user = await env.DB.prepare(
    'SELECT * FROM users WHERE id=?'
  ).bind(session.email).first();

  await env.DB.prepare(
    'UPDATE notifications SET is_read=1, read_at=? WHERE id=? AND user_id=?'
  ).bind(new Date().toISOString(), notifId, user.id).run();

  return json({ success: true });
}

// ─────────────────────────────────────────────
// POST /notifications/read-all
// 全通知を既読にする
// ─────────────────────────────────────────────
if (method === 'POST' && path === '/notifications/read-all') {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) return json({ error: '認証が必要です' }, 401);

  const session = await env.DB.prepare(
    'SELECT * FROM sessions WHERE token=? AND expires>?'
  ).bind(token, new Date().toISOString()).first();
  if (!session) return json({ error: 'セッション無効' }, 401);

  const user = await env.DB.prepare(
    'SELECT * FROM users WHERE id=?'
  ).bind(session.email).first();

  await env.DB.prepare(
    'UPDATE notifications SET is_read=1, read_at=? WHERE user_id=? AND is_read=0'
  ).bind(new Date().toISOString(), user.id).run();

  return json({ success: true });
}

// ─────────────────────────────────────────────
// POST /coupons/apply
// クーポンを適用する
// ─────────────────────────────────────────────
if (method === 'POST' && path === '/coupons/apply') {
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) return json({ error: '認証が必要です' }, 401);

  const session = await env.DB.prepare(
    'SELECT * FROM sessions WHERE token=? AND expires>?'
  ).bind(token, new Date().toISOString()).first();
  if (!session) return json({ error: 'セッション無効' }, 401);

  const user = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(session.email).first();
  const { coupon_code, module_id } = await request.json();

  const coupon = await env.DB.prepare(
    'SELECT * FROM coupons WHERE code=? AND is_active=1'
  ).bind(coupon_code).first();

  if (!coupon) return json({ error: '無効なクーポンコードです' });

  const now = new Date().toISOString();
  if (coupon.valid_until && coupon.valid_until < now) return json({ error: 'このクーポンは期限切れです' });
  if (coupon.valid_from > now) return json({ error: 'このクーポンはまだ使用できません' });
  if (coupon.max_uses && coupon.used_count >= coupon.max_uses) return json({ error: '使用上限に達したクーポンです' });

  const used = await env.DB.prepare(
    'SELECT id FROM coupon_usages WHERE coupon_id=? AND org_id=?'
  ).bind(coupon.id, user.org_id || user.id).first();
  if (used) return json({ error: 'このクーポンは既に使用済みです' });

  if (coupon.target_module_id && coupon.target_module_id !== module_id) {
    return json({ error: 'このクーポンはこのモジュールには使用できません' });
  }

  // subscriptionを取得（なければ作成）
  let sub = await env.DB.prepare(
    'SELECT * FROM subscriptions WHERE org_id=? AND module_id=?'
  ).bind(user.org_id || user.id, module_id).first();

  if (!sub) {
    const subId = crypto.randomUUID();
    await env.DB.prepare(
      'INSERT INTO subscriptions (id,org_id,module_id,status,started_at,created_at) VALUES (?,?,?,?,?,?)'
    ).bind(subId, user.org_id || user.id, module_id, 'trial', now, now).run();
    sub = await env.DB.prepare('SELECT * FROM subscriptions WHERE id=?').bind(subId).first();
  }

  // 無料月数を付与
  if (coupon.discount_type === 'free_months') {
    const trialEnd = new Date();
    trialEnd.setMonth(trialEnd.getMonth() + coupon.discount_value);
    await env.DB.prepare(
      'UPDATE subscriptions SET trial_end_at=?, coupon_code=?, free_months_remaining=?, status=? WHERE id=?'
    ).bind(trialEnd.toISOString(), coupon_code, coupon.discount_value, 'trial', sub.id).run();
  }

  // 使用記録
  await env.DB.prepare(
    'INSERT INTO coupon_usages (id,coupon_id,org_id,used_at,applied_to) VALUES (?,?,?,?,?)'
  ).bind(crypto.randomUUID(), coupon.id, user.org_id || user.id, now, sub.id).run();

  await env.DB.prepare(
    'UPDATE coupons SET used_count=used_count+1 WHERE id=?'
  ).bind(coupon.id).run();

  return json({ success: true, message: coupon.name + 'が適用されました！' });
}
