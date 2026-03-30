// ══════════════════════════════════════════════════════════════
// viralio-credits-upsell.js — Script partajat pentru TOATE sub-aplicațiile
// ══════════════════════════════════════════════════════════════
//
// INSTALARE (în fiecare sub-aplicație, înainte de </body>):
//
//   <script src="https://viralio.ro/viralio-credits-upsell.js"></script>
//
// UTILIZARE — interceptează generarea/voice înainte de a consuma credite:
//
//   // În loc să apelezi direct API-ul, apelezi mai întâi:
//   if (!window.ViralioUpsell.checkBeforeGenerate(userObject)) return; // oprește dacă 0 credite
//   // ... rest logică generare
//
//   // Pentru voice:
//   if (!window.ViralioUpsell.checkBeforeVoice(userObject)) return;
//
//   // La login / refresh user:
//   window.ViralioUpsell.onUserLoaded(userObject);
//
// ══════════════════════════════════════════════════════════════

(function () {
    'use strict';

    // ── Config ────────────────────────────────────────────────
    const HUB_URL         = 'https://viralio.ro';
    const TTL_LOW         = 48 * 60 * 60 * 1000; // 48h — popup "sub 20%"
    const LS_LOW_KEY      = 'viralio_upsell_low_shown';

    const PLAN_CREDITS_MAP = { starter: 150, creator: 400, agency: 1500, none: 10 };
    const UPGRADE_OPTIONS  = {
        none:    ['starter', 'creator', 'agency'],
        starter: ['creator', 'agency'],
        creator: ['agency'],
        agency:  [],
    };
    const PLAN_LABELS   = { starter: 'Starter', creator: 'Creator PRO', agency: 'Agency' };
    const PLAN_PRICES   = { starter: '49.90',   creator: '99.90',       agency: '249.90' };
    const PLAN_CREDITS  = { starter: '150',      creator: '400',         agency: '1.500' };
    const PLAN_HIGHLIGHT = { starter: false, creator: true, agency: false };

    // ── Injectează CSS + HTML modal ───────────────────────────
    function injectUI() {
        if (document.getElementById('vu-modal')) return; // deja injectat

        // ── Styles ──
        const style = document.createElement('style');
        style.textContent = `
            #vu-modal { display:none;opacity:0;pointer-events:none;position:fixed;inset:0;z-index:2000000;
                align-items:flex-end;justify-content:center;background:rgba(9,9,11,0.82);
                backdrop-filter:blur(10px);transition:opacity .3s; }
            @media(min-width:640px){ #vu-modal { align-items:center; } }
            #vu-modal.vu-show { opacity:1;pointer-events:auto;display:flex !important; }
            #vu-box { width:100%;max-width:480px;background:#09090b;border:1px solid rgba(255,255,255,0.1);
                border-radius:2rem 2rem 0 0;padding:2rem;box-shadow:0 25px 60px rgba(0,0,0,0.6);
                position:relative;overflow:hidden;transform:translateY(40px);transition:transform .3s; }
            @media(min-width:640px){ #vu-box { border-radius:2rem;transform:translateY(0); } }
            #vu-modal.vu-show #vu-box { transform:translateY(0); }
            #vu-box .vu-glow1 { position:absolute;top:-80px;right:-80px;width:220px;height:220px;
                background:rgba(99,102,241,0.15);filter:blur(70px);border-radius:50%;pointer-events:none; }
            #vu-box .vu-glow2 { position:absolute;bottom:-80px;left:-80px;width:220px;height:220px;
                background:rgba(236,72,153,0.1);filter:blur(70px);border-radius:50%;pointer-events:none; }
            #vu-close-btn { position:absolute;top:14px;right:14px;width:32px;height:32px;border-radius:50%;
                background:rgba(255,255,255,0.05);color:#94a3b8;border:none;cursor:pointer;
                display:flex;align-items:center;justify-content:center;transition:all .2s;font-size:14px;z-index:10; }
            #vu-close-btn:hover { background:rgba(255,255,255,0.1);color:#fff; }
            #vu-tabs { display:flex;gap:6px;background:rgba(255,255,255,0.05);padding:4px;
                border-radius:12px;margin-bottom:16px; }
            .vu-tab { flex:1;padding:8px;border-radius:8px;border:none;cursor:pointer;font-size:12px;
                font-weight:700;transition:all .2s;background:transparent;color:#64748b; }
            .vu-tab.vu-active { background:rgba(255,255,255,0.12);color:#fff; }
            #vu-panel-topup, #vu-panel-upgrade { display:flex;flex-direction:column;gap:10px; }
            .vu-topup-btn { width:100%;display:flex;align-items:center;justify-content:space-between;
                background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);
                border-radius:16px;padding:14px 18px;cursor:pointer;transition:all .2s;text-align:left; }
            .vu-topup-btn:hover { background:rgba(255,255,255,0.09);border-color:rgba(245,158,11,0.35); }
            .vu-topup-btn.vu-popular { border-color:rgba(245,158,11,0.35);position:relative;overflow:hidden; }
            .vu-popular-badge { position:absolute;top:0;right:0;background:#f59e0b;color:#09090b;
                font-size:0.5rem;font-weight:900;padding:3px 10px;border-radius:0 0 0 10px;
                text-transform:uppercase;letter-spacing:.08em; }
            .vu-plan-btn { width:100%;display:flex;align-items:center;justify-content:space-between;
                border-radius:16px;padding:14px 18px;cursor:pointer;transition:all .2s;text-align:left;border:none; }
            .vu-progress-wrap { background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);
                border-radius:16px;padding:16px;margin-bottom:16px; }
            .vu-progress-track { width:100%;height:10px;background:rgba(255,255,255,0.1);
                border-radius:99px;overflow:hidden;margin:8px 0; }
            .vu-progress-fill { height:100%;border-radius:99px;transition:width .7s; }
            .vu-benefits { display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px; }
            .vu-benefit { background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);
                border-radius:12px;padding:10px 12px; }
        `;
        document.head.appendChild(style);

        // ── Modal HTML ──
        const modal = document.createElement('div');
        modal.id = 'vu-modal';
        modal.innerHTML = `
            <div id="vu-box">
                <div class="vu-glow1"></div>
                <div class="vu-glow2"></div>
                <button id="vu-close-btn" onclick="window.ViralioUpsell._close()">✕</button>

                <!-- Header (se schimbă dinamic) -->
                <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;position:relative;z-index:1">
                    <div id="vu-icon" style="width:44px;height:44px;border-radius:12px;background:rgba(245,158,11,0.2);
                        display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:20px">⚠️</div>
                    <div>
                        <p id="vu-subtitle" style="color:#64748b;font-size:11px;font-weight:700;text-transform:uppercase;
                            letter-spacing:.1em;margin-bottom:4px">Atenție</p>
                        <h3 id="vu-title" style="color:#fff;font-weight:900;font-size:17px;line-height:1.2;margin:0">
                            Creditele tale se termină curând!
                        </h3>
                    </div>
                </div>

                <!-- Progress bar credite -->
                <div class="vu-progress-wrap" style="position:relative;z-index:1">
                    <div style="display:flex;justify-content:space-between;align-items:center">
                        <span style="color:#94a3b8;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em">
                            ⚡ Credite rămase
                        </span>
                        <span style="color:#fff;font-weight:900;font-size:13px">
                            <span id="vu-cr-left">0</span> / <span id="vu-cr-total">0</span>
                        </span>
                    </div>
                    <div class="vu-progress-track">
                        <div id="vu-progress-fill" class="vu-progress-fill" style="width:2%;background:linear-gradient(90deg,#ef4444,#b91c1c)"></div>
                    </div>
                    <p id="vu-videos-left-text" style="color:#64748b;font-size:11px;font-weight:500;margin:6px 0 0">
                        Mai poți genera aproximativ <span id="vu-videos-left" style="color:#f59e0b;font-weight:700">—</span> videoclipuri 1080p
                    </p>
                </div>

                <!-- Tabs -->
                <div id="vu-tabs" style="position:relative;z-index:1">
                    <button class="vu-tab vu-active" id="vu-tab-topup"    onclick="window.ViralioUpsell._tab('topup')">⚡ Top-up Rapid</button>
                    <button class="vu-tab"            id="vu-tab-upgrade"  onclick="window.ViralioUpsell._tab('upgrade')">🚀 Upgrade Plan</button>
                </div>

                <!-- Panel: top-up -->
                <div id="vu-panel-topup" style="position:relative;z-index:1">
                    <button class="vu-topup-btn" onclick="window.ViralioUpsell._buyTopup('micro')">
                        <div>
                            <div style="color:#fff;font-weight:900;font-size:13px">50 Credite</div>
                            <div style="color:#64748b;font-size:11px;font-weight:500;margin-top:2px">≈ 25 videoclipuri 1080p</div>
                        </div>
                        <div style="text-align:right">
                            <div style="color:#f59e0b;font-weight:900;font-size:15px">19.90 <span style="font-size:11px;color:#64748b">RON</span></div>
                            <div style="color:#475569;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-top:2px">fără abonament</div>
                        </div>
                    </button>
                    <button class="vu-topup-btn vu-popular" onclick="window.ViralioUpsell._buyTopup('standard')">
                        <span class="vu-popular-badge">Popular</span>
                        <div>
                            <div style="color:#fff;font-weight:900;font-size:13px">150 Credite</div>
                            <div style="color:#64748b;font-size:11px;font-weight:500;margin-top:2px">≈ 75 videoclipuri 1080p</div>
                        </div>
                        <div style="text-align:right">
                            <div style="color:#f59e0b;font-weight:900;font-size:15px">54.90 <span style="font-size:11px;color:#64748b">RON</span></div>
                            <div style="color:#475569;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-top:2px">0.37 RON/cr</div>
                        </div>
                    </button>
                    <button class="vu-topup-btn" onclick="window.ViralioUpsell._buyTopup('pro')">
                        <div>
                            <div style="color:#fff;font-weight:900;font-size:13px">400 Credite</div>
                            <div style="color:#64748b;font-size:11px;font-weight:500;margin-top:2px">≈ 200 videoclipuri 1080p</div>
                        </div>
                        <div style="text-align:right">
                            <div style="color:#f59e0b;font-weight:900;font-size:15px">139.90 <span style="font-size:11px;color:#64748b">RON</span></div>
                            <div style="color:#475569;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-top:2px">0.35 RON/cr</div>
                        </div>
                    </button>
                    <p style="text-align:center;color:#475569;font-size:10px;font-weight:500;margin-top:4px">
                        Creditele de top-up nu expiră niciodată.
                    </p>
                </div>

                <!-- Panel: upgrade -->
                <div id="vu-panel-upgrade" style="display:none;position:relative;z-index:1;flex-direction:column;gap:10px">
                    <div class="vu-benefits">
                        <div class="vu-benefit">
                            <p style="color:#fff;font-size:11px;font-weight:700;margin:0 0 2px">⚡ Mai multe credite lunar</p>
                            <p style="color:#475569;font-size:10px;font-weight:500;margin:0">Reset automat în fiecare lună</p>
                        </div>
                        <div class="vu-benefit">
                            <p style="color:#fff;font-size:11px;font-weight:700;margin:0 0 2px">☁️ Istoric cloud salvat</p>
                            <p style="color:#475569;font-size:10px;font-weight:500;margin:0">30 zile → permanent</p>
                        </div>
                        <div class="vu-benefit">
                            <p style="color:#fff;font-size:11px;font-weight:700;margin:0 0 2px">🚀 Procesare prioritară</p>
                            <p style="color:#475569;font-size:10px;font-weight:500;margin:0">Generezi înaintea altora</p>
                        </div>
                        <div class="vu-benefit">
                            <p style="color:#fff;font-size:11px;font-weight:700;margin:0 0 2px">🎙️ 3× mai multe litere voce</p>
                            <p style="color:#475569;font-size:10px;font-weight:500;margin:0">150k → 500k caractere</p>
                        </div>
                    </div>
                    <div id="vu-plan-cards" style="display:flex;flex-direction:column;gap:8px"></div>
                    <p style="text-align:center;color:#475569;font-size:10px;font-weight:500;margin-top:4px">
                        Anulezi oricând. Fără contract.
                    </p>
                </div>
            </div>
        `;
        document.body.appendChild(modal);

        // Închide la click pe backdrop
        modal.addEventListener('click', function (e) {
            if (e.target === modal) window.ViralioUpsell._close();
        });
    }

    // ── Helpers ───────────────────────────────────────────────
    function lsGet(key) {
        try { return localStorage.getItem(key); } catch (e) { return null; }
    }
    function lsSet(key, val) {
        try { localStorage.setItem(key, val); } catch (e) {}
    }

    function cooldownOk(lsKey, ttl) {
        const last = lsGet(lsKey);
        if (!last) return true;
        return (Date.now() - parseInt(last, 10)) > ttl;
    }

    function markShown(lsKey) {
        lsSet(lsKey, Date.now().toString());
    }

    // ── Logica principală ─────────────────────────────────────
    function checkLow(user) {
        const plan       = user.subscriptionPlan || 'none';
        const credits    = user.credits || 0;
        const total      = PLAN_CREDITS_MAP[plan] || 10;
        const pct        = credits / total;

        if (pct <= 0.20 && credits > 0 && cooldownOk(LS_LOW_KEY, TTL_LOW)) {
            setTimeout(function () {
                _open({
                    mode:    'low',
                    credits: credits,
                    total:   total,
                    plan:    plan,
                    status:  user.subscriptionStatus || 'inactive',
                });
                markShown(LS_LOW_KEY);
            }, 2000);
        }
    }

    // ── Deschide modalul ──────────────────────────────────────
    function _open(opts) {
        injectUI();

        const isEmpty = opts.mode === 'empty';
        const credits = opts.credits || 0;
        const total   = opts.total   || PLAN_CREDITS_MAP[opts.plan] || 10;
        const plan    = opts.plan    || 'none';
        const status  = opts.status  || 'inactive';
        const isVoice = opts.isVoice || false;

        // ── Header dinamic ──
        const icon     = document.getElementById('vu-icon');
        const subtitle = document.getElementById('vu-subtitle');
        const title    = document.getElementById('vu-title');

        if (isEmpty && isVoice) {
            icon.textContent      = '🎙️';
            icon.style.background = 'rgba(99,102,241,0.2)';
            subtitle.textContent  = 'Caractere voce epuizate';
            title.textContent     = 'Nu mai ai litere voce disponibile!';
        } else if (isEmpty) {
            icon.textContent      = '🔴';
            icon.style.background = 'rgba(239,68,68,0.2)';
            subtitle.textContent  = 'Credite epuizate';
            title.textContent     = 'Nu mai ai credite! Reîncarcă acum.';
        } else {
            icon.textContent      = '⚠️';
            icon.style.background = 'rgba(245,158,11,0.2)';
            subtitle.textContent  = 'Atenție';
            title.textContent     = 'Creditele tale se termină curând!';
        }

        // ── Progress bar ──
        const pct  = isEmpty ? 0 : Math.max(2, Math.round((credits / total) * 100));
        const fill = document.getElementById('vu-progress-fill');
        fill.style.width = pct + '%';
        fill.style.background = pct <= 10
            ? 'linear-gradient(90deg,#ef4444,#b91c1c)'
            : 'linear-gradient(90deg,#f59e0b,#ef4444)';

        document.getElementById('vu-cr-left').textContent  = credits;
        document.getElementById('vu-cr-total').textContent = total;

        const videos = Math.floor(credits / 2);
        document.getElementById('vu-videos-left').textContent =
            videos > 0 ? videos : (isEmpty ? '0' : 'mai puțin de 1');

        const videosText = document.getElementById('vu-videos-left-text');
        if (isEmpty && isVoice) {
            videosText.innerHTML = 'Activează sau reîncarcă planul pentru a continua voiceover-ul.';
        } else if (isEmpty) {
            videosText.innerHTML = 'Fără credite nu poți genera conținut. Reîncarcă acum!';
        } else {
            videosText.innerHTML = 'Mai poți genera aproximativ <span id="vu-videos-left" style="color:#f59e0b;font-weight:700">' + (videos > 0 ? videos : 'mai puțin de 1') + '</span> videoclipuri 1080p';
        }

        // ── Tabs & planuri ──
        _buildPlanCards(plan, status);
        const upgrades = UPGRADE_OPTIONS[plan] || [];
        if (upgrades.length === 0) {
            document.getElementById('vu-tab-upgrade').style.display = 'none';
            _tab('topup');
        } else {
            document.getElementById('vu-tab-upgrade').style.display = '';
            // Dacă e empty și nu are plan → arată upgrade primul
            _tab((isEmpty && plan === 'none') ? 'upgrade' : (plan === 'none' ? 'upgrade' : 'topup'));
        }

        // ── Afișează ──
        const modal = document.getElementById('vu-modal');
        modal.style.display = 'flex';
        requestAnimationFrame(function () {
            requestAnimationFrame(function () {
                modal.classList.add('vu-show');
            });
        });
    }

    function _buildPlanCards(currentPlan, status) {
        const container = document.getElementById('vu-plan-cards');
        const upgrades  = UPGRADE_OPTIONS[currentPlan] || [];
        container.innerHTML = '';

        upgrades.forEach(function (plan) {
            const hl  = PLAN_HIGHLIGHT[plan];
            const btn = document.createElement('button');
            btn.className = 'vu-plan-btn';
            btn.style.cssText = hl
                ? 'background:linear-gradient(135deg,rgba(99,102,241,0.15),rgba(236,72,153,0.1));border:1.5px solid rgba(99,102,241,0.4)'
                : 'background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1)';
            btn.innerHTML = `
                <div>
                    <div style="display:flex;align-items:center;gap:6px">
                        <span style="color:#fff;font-weight:900;font-size:13px">${PLAN_LABELS[plan]}</span>
                        ${hl ? '<span style="font-size:9px;font-weight:900;padding:2px 8px;border-radius:4px;background:linear-gradient(90deg,#6366f1,#ec4899);color:#fff;text-transform:uppercase;letter-spacing:.08em">Recomandat</span>' : ''}
                    </div>
                    <div style="color:#475569;font-size:11px;font-weight:500;margin-top:2px">${PLAN_CREDITS[plan]} credite/lună · Reset automat</div>
                </div>
                <div style="text-align:right;flex-shrink:0;margin-left:12px">
                    <div style="color:#f59e0b;font-size:15px;font-weight:900">${PLAN_PRICES[plan]} <span style="font-size:11px;font-weight:700;color:#64748b">RON/lună</span></div>
                    ${status === 'active' ? '<div style="font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:.05em;margin-top:2px">upgrade instant</div>' : ''}
                </div>
            `;
            btn.onclick = function () {
                window.ViralioUpsell._close();
                _redirectSubscribe(plan);
            };
            container.appendChild(btn);
        });
    }

    function _redirectSubscribe(plan) {
        // Redirectează la hub cu planul presetat
        window.location.href = HUB_URL + '/#pricing?plan=' + plan;
    }

    // ── API publică ───────────────────────────────────────────
    window.ViralioUpsell = {

        // Apelat la fiecare login / refresh user
        onUserLoaded: function (user) {
            if (!user) return;
            checkLow(user);
        },

        // Apelat ÎNAINTE de a consuma credite pt generare
        // Returnează FALSE dacă nu are credite (și deschide modalul — de fiecare dată)
        checkBeforeGenerate: function (user) {
            if (!user) return false;
            const credits = user.credits || 0;
            if (credits <= 0) {
                _open({
                    mode:    'empty',
                    credits: 0,
                    total:   PLAN_CREDITS_MAP[user.subscriptionPlan || 'none'] || 10,
                    plan:    user.subscriptionPlan || 'none',
                    status:  user.subscriptionStatus || 'inactive',
                    isVoice: false,
                });
                return false;
            }
            return true;
        },

        // Apelat ÎNAINTE de a consuma voice characters
        checkBeforeVoice: function (user) {
            if (!user) return false;
            const chars = user.voice_characters || 0;
            if (chars <= 0) {
                _open({
                    mode:    'empty',
                    credits: user.credits || 0,
                    total:   PLAN_CREDITS_MAP[user.subscriptionPlan || 'none'] || 10,
                    plan:    user.subscriptionPlan || 'none',
                    status:  user.subscriptionStatus || 'inactive',
                    isVoice: true,
                });
                return false;
            }
            return true;
        },

        // Deschide manual (dacă ai nevoie)
        open: _open,

        // ── Interne (folosite din HTML) ────────────────────────
        _close: function () {
            const modal = document.getElementById('vu-modal');
            if (!modal) return;
            modal.classList.remove('vu-show');
            setTimeout(function () { modal.style.display = 'none'; }, 300);
        },

        _tab: function (tab) { _tab(tab); },

        _buyTopup: function (pkg) {
            window.ViralioUpsell._close();
            // Dacă sub-app-ul are propria funcție buyTopup, o folosim
            if (typeof window.buyTopup === 'function') {
                window.buyTopup(pkg);
            } else {
                // Fallback: redirect la hub
                window.location.href = HUB_URL + '/?topup=' + pkg + '#topup';
            }
        },
    };

    function _tab(tab) {
        const topup   = document.getElementById('vu-panel-topup');
        const upgrade = document.getElementById('vu-panel-upgrade');
        const tabTop  = document.getElementById('vu-tab-topup');
        const tabUp   = document.getElementById('vu-tab-upgrade');
        if (!topup) return;
        topup.style.display   = tab === 'topup'   ? 'flex' : 'none';
        upgrade.style.display = tab === 'upgrade' ? 'flex' : 'none';
        tabTop.classList.toggle('vu-active',  tab === 'topup');
        tabUp.classList.toggle('vu-active',   tab === 'upgrade');
    }

    // ── Auto-inject UI când DOM e ready ──────────────────────
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', injectUI);
    } else {
        injectUI();
    }

})();
