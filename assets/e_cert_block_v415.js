/**
 * 電子署名 + タイムスタンプ証明書ブロック 共通モジュール v4.15
 *
 * 目的: 同意書3テンプレ（consent_form_template / consent_form_acupuncture_template
 *       / consent_form_massage_template）で実装している電子署名認証バナー +
 *       タイムスタンプ証明書ブロックを、他の帳票テンプレ（退院通知 / NDA / 施術報告書 /
 *       退院時共同指導記録 / 担当者会議記録 / モニタリング記録）でも再利用可能にする。
 *
 * 使い方:
 *   1. 帳票HTMLの <head> 内で本JSを読み込む:
 *        <link rel="stylesheet" href="assets/e_cert_block_v415.css">
 *        <script src="assets/e_cert_block_v415.js"></script>
 *   2. ブロックを差し込みたい位置に空のコンテナを置く:
 *        <div id="e-cert-mount"></div>
 *        <div id="timestamp-cert-mount"></div>
 *   3. レンダ関数の最後で呼び出す:
 *        window.eCertBlockRender('#e-cert-mount', '#timestamp-cert-mount', {
 *          signer: '田中 太郎',
 *          signed_at: '2026-05-25T10:00:00+09:00',
 *          tsa_authority: 'SEIKO',
 *          timestamp: { authority_name, cert_no, acquired_at, serial, hash_algorithm, document_hash },
 *          sd_id, content_hash, chain_index
 *        });
 *
 * 法的根拠:
 *   - e-文書法（平成16年法律第149号）
 *   - 電子署名法（平成12年法律第102号）
 *   - 認定タイムスタンプ業務（令和3年法律第146号 第3条第1項）
 *   - RFC 3161 (TSP: Time-Stamp Protocol)
 */
(function(global){
  'use strict';

  function fmtJST(iso){
    if(!iso) return '—';
    try{
      const d = new Date(iso);
      const y = d.getFullYear(), m = String(d.getMonth()+1).padStart(2,'0'), dd = String(d.getDate()).padStart(2,'0');
      const hh = String(d.getHours()).padStart(2,'0'), mi = String(d.getMinutes()).padStart(2,'0');
      return `${y}-${m}-${dd} ${hh}:${mi}`;
    }catch(e){ return iso; }
  }

  function escapeHtml(s){
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  /**
   * 電子署名認証バナー（シアン枠）を mount に挿入
   * @param {string|Element} mount - セレクタまたは DOM 要素
   * @param {object} opts - { signer, signed_at, tsa_authority }
   */
  function renderECertBanner(mount, opts){
    const el = typeof mount === 'string' ? document.querySelector(mount) : mount;
    if(!el) return;
    const signer = escapeHtml(opts.signer || '—');
    const ts = fmtJST(opts.signed_at);
    const auth = escapeHtml((opts.tsa_authority || 'SEIKO').toUpperCase());
    el.innerHTML = `
      <div class="e-cert-banner">
        <div class="e-cert-icon">✓</div>
        <div class="e-cert-body">
          <div class="e-cert-title">電子署名 + タイムスタンプ済</div>
          <div>本書面は <strong>e-文書法・電子署名法</strong> に準拠した電子署名と、第三者機関のタイムスタンプを付与した上で、<strong>SHA-256 ハッシュチェーン</strong> に登録された原本性保証付き文書です。</div>
          <div class="e-cert-row">
            <span>署名者: <strong>${signer}</strong></span>
            <span>タイムスタンプ: <strong>${ts}</strong></span>
            <span>認証局: <strong>${auth}</strong></span>
          </div>
        </div>
      </div>
    `;
  }

  /**
   * タイムスタンプ証明書ブロック（紫枠）を mount に挿入
   * @param {string|Element} mount - セレクタまたは DOM 要素
   * @param {object} ts - timestamp オブジェクト { authority_name, cert_no, acquired_at, serial, hash_algorithm, document_hash }
   */
  function renderTimestampCert(mount, ts){
    const el = typeof mount === 'string' ? document.querySelector(mount) : mount;
    if(!el || !ts) return;
    const acquiredJst = ts.acquired_at ? fmtJST(ts.acquired_at) + ' (JST / UTC+09:00)' : '—';
    const acquiredUtc = ts.acquired_at || '—';
    el.innerHTML = `
      <div class="timestamp-cert">
        <h4>🕒 タイムスタンプ証明書</h4>
        <div class="ts-subtitle">総務省 認定タイムスタンプ業務（時刻認証業務）準拠 / RFC 3161 (TSP)</div>
        <dl class="ts-grid">
          <dt>認定タイムスタンプ事業者</dt><dd>${escapeHtml(ts.authority_name || '—')}</dd>
          <dt>認定番号</dt><dd>${escapeHtml(ts.cert_no || '—')}</dd>
          <dt>付与日時 (JST)</dt><dd>${acquiredJst}</dd>
          <dt>付与日時 (UTC)</dt><dd>${escapeHtml(acquiredUtc)}</dd>
          <dt>シリアル番号</dt><dd>${escapeHtml(ts.serial || '—')}</dd>
          <dt>ハッシュアルゴリズム</dt><dd>${escapeHtml(ts.hash_algorithm || 'SHA-256')}</dd>
          <dt>対象文書ハッシュ</dt><dd class="ts-hash">${escapeHtml(ts.document_hash || '—')}</dd>
        </dl>
        <p class="ts-note">本タイムスタンプは <strong>総務省「認定タイムスタンプ業務」</strong>（令和3年法律第146号 第3条第1項）に基づく認定事業者により付与され、文書が <strong>付与時刻に存在し、それ以降改ざんされていない</strong> ことを証明します。検証は QR コードまたは認定局の検証窓口にて可能。</p>
      </div>
    `;
  }

  /**
   * 一括レンダリング（バナー＋タイムスタンプ証明書を両方差し込む）
   */
  function eCertBlockRender(bannerMount, tsMount, data){
    if(data.signature && data.signature.signed_at){
      renderECertBanner(bannerMount, {
        signer: data.signer,
        signed_at: data.signature.signed_at,
        tsa_authority: (data.timestamp && data.timestamp.authority) || data.tsa?.authority || 'SEIKO'
      });
    }
    if(data.timestamp){
      renderTimestampCert(tsMount, data.timestamp);
    }
  }

  global.eCertBlockRender = eCertBlockRender;
  global.renderECertBanner = renderECertBanner;
  global.renderTimestampCert = renderTimestampCert;
})(typeof window !== 'undefined' ? window : global);
