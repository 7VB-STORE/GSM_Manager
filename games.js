const https = require('https');
const querystring = require('querystring');
const SteamUser = require('steam-user');
const SteamTotp = require('steam-totp');

// Account Manager Games helper.
// Commands:
//   list <login> <password> <shared_secret> <steamid>
//   add  <login> <password> <shared_secret> <steamid> <target>
// target may be AppID, SubID (subid:123), or a Steam store URL.

const [, , command, targetArg] = process.argv;
const login = process.env.SHARK_STEAM_LOGIN || '';
const password = process.env.SHARK_STEAM_PASSWORD || '';
const sharedSecret = process.env.SHARK_STEAM_SHARED_SECRET || '';
const steamId = process.env.SHARK_STEAM_ID || '';
const refreshToken = process.env.SHARK_STEAM_REFRESH_TOKEN || '';

if (!command || !login || !steamId || (!refreshToken && (!password || !sharedSecret))) {
    console.error('Usage: node games.js <list|add> [appid|subid:ID|store URL]');
    process.exit(2);
}

function out(obj) {
    try { process.stdout.write(JSON.stringify(obj) + '\n'); } catch (_) {}
}
function log(level, message) { out({type:'log', level, message:String(message || '')}); }
function finish(result, code) {
    if (finished) return;
    // Mark the helper as finished BEFORE logOff(). Steam emits a
    // `disconnected` event when we intentionally close a successful session;
    // without this guard that normal shutdown was being reported to the UI as
    // "Steam disconnected: Logged off" and overwrote the success result.
    finished = true;
    try { client.logOff(); } catch (_) {}
    out(result);
    setTimeout(() => process.exit(code === undefined ? (result.ok ? 0 : 1) : code), 250);
}

function extractTarget(value) {
    const raw = String(value || '').trim();
    if (!raw) return null;
    const subMatch = raw.match(/(?:\/sub\/|subid\D*)(\d+)/i);
    if (subMatch) {
        const id = Number.parseInt(subMatch[1], 10);
        return Number.isInteger(id) && id > 0 ? {type:'sub', id} : null;
    }
    const appMatch = raw.match(/\/app\/(\d+)/i);
    if (appMatch) {
        const id = Number.parseInt(appMatch[1], 10);
        return Number.isInteger(id) && id > 0 ? {type:'app', id} : null;
    }
    if (/^\d+$/.test(raw)) {
        const id = Number.parseInt(raw, 10);
        return Number.isInteger(id) && id > 0 ? {type:'app', id} : null;
    }
    return null;
}

const target = extractTarget(targetArg);
if (command === 'add' && !target) {
    out({ok:false, error:'Некорректный AppID/SubID/Steam store URL'});
    process.exit(2);
}

let finished = false;
let webSessionId = null;
let webCookies = [];
let latestRefreshToken = refreshToken || '';

// Create the Steam client before attaching any listeners.
// Otherwise Node.js throws:
// ReferenceError: Cannot access 'client' before initialization
const usingSavedSession = !!refreshToken;
// Do not rotate a valid refresh session on every request. A new session/token
// is created only when we have to authenticate with login/password again.
const client = new SteamUser({ enablePicsCache: true, renewRefreshTokens: false });

client.on('refreshToken', token => {
    if (token) latestRefreshToken = String(token);
    log('INFO', 'Steam refresh token received/renewed');
});

function cookieHeader() { return webCookies.join('; '); }
function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }


function fetchAuthenticatedText(url, extraHeaders = {}) {
    return fetchText(url, {
        Cookie: cookieHeader(),
        Referer: 'https://store.steampowered.com/',
        ...extraHeaders
    });
}

// A redirect is not proof that a free package was claimed. Verify the
// account's actual license list instead. This also works for DLC packages
// which may never appear in the normal owned-games list.
async function confirmStoreLicense(subId, waitMs = 12000) {
    const deadline = Date.now() + waitMs;
    const needle = String(subId);

    while (Date.now() < deadline) {
        try {
            const html = await fetchAuthenticatedText('https://store.steampowered.com/account/licenses/?l=english');
            const patterns = [
                new RegExp('RemoveFreeLicense\\s*\\(\\s*' + needle + '\\b', 'i'),
                new RegExp('\\bsubid\\s*[=:]\\s*[' + '"' + '\']?' + needle + '\\b', 'i'),
                new RegExp('/sub/' + needle + '(?:\\D|$)', 'i'),
            ];
            if (patterns.some(re => re.test(html))) return true;
        } catch (_) {}

        try {
            const licenses = Array.isArray(client.licenses) ? client.licenses : [];
            if (licenses.some(license => Number(license?.packageid) === Number(subId))) return true;
        } catch (_) {}

        await delay(1500);
    }
    return false;
}

function fetchText(url, headers = {}) {
    return new Promise((resolve, reject) => {
        const req = https.get(url, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/154.0 Safari/537.36',
                ...headers
            }
        }, response => {
            let body = '';
            response.setEncoding('utf8');
            response.on('data', chunk => body += chunk);
            response.on('end', () => {
                if (response.statusCode !== 200) {
                    reject(new Error(`HTTP ${response.statusCode} for ${url}`));
                    return;
                }
                resolve(body);
            });
        });
        req.on('error', reject);
        req.setTimeout(20000, () => req.destroy(new Error('Steam store request timeout')));
    });
}

// A 100%-off promotional DLC is often represented by a temporary SubID,
// not by an AppID license. requestFreeLicense(AppID) can therefore return
// no grants even though the store page has an "Add to Account" button.
// Discover the promotional SubID from the Steam store page and use the same
// addfreelicense request that the store itself uses.
async function discoverFreePromoSubIds(appId) {
    const candidates = new Map();
    const addCandidate = (id, score, reason) => {
        const n = Number(id);
        if (!Number.isInteger(n) || n <= 0) return;
        const old = candidates.get(n) || {id:n, score:0, reasons:[]};
        old.score = Math.max(old.score, Number(score) || 0);
        if (reason && !old.reasons.includes(reason)) old.reasons.push(reason);
        candidates.set(n, old);
    };

    // Only accept a package when its own store block proves that the offer
    // costs nothing. A nearby "Free" label or another discounted package is
    // not enough: those false matches were the source of wrong SubID claims.
    const zeroPriceBlock = block => {
        const text = String(block || '').replace(/&nbsp;/gi, ' ').replace(/\s+/g, ' ');
        const discount100 = /(?:discount_pct[^>]*>\s*)?-100%|100%\s*off|discount_percent(?:\\?")?\s*:\s*100/i.test(text);
        const finalZero = /(?:discount_final_price|discount_prices|game_purchase_price|price)[^<]{0,100}>\s*(?:Free|0(?:[.,]00)?)(?:\s|&|<|$)/i.test(text)
            || /final(?:_price)?(?:\\?")?\s*:\s*0\b/i.test(text);
        const addFree = /addfreelicense|AddFreeLicense|add to account/i.test(text);
        return addFree && (discount100 || finalZero);
    };

    try {
        const html = await fetchText(`https://store.steampowered.com/app/${appId}/?l=english&cc=us`);
        const blockRe = /<div\b[^>]*(?:game_area_purchase_game|game_purchase_action)[\s\S]*?(?=<div\b[^>]*game_area_purchase_game|<div\b[^>]*rightcol|$)/gi;
        let match;
        while ((match = blockRe.exec(html)) !== null) {
            const block = match[0];
            if (!zeroPriceBlock(block)) continue;
            const ids = new Set();
            const patterns = [
                /subid\s*[:=]\s*["']?(\d+)/ig,
                /data-ds-packageid=["'](\d+)["']/ig,
                /data-packageid=["'](\d+)["']/ig,
                /\/sub\/(\d+)/ig,
                /addfreelicense(?:\/|[^0-9]{0,40})(\d+)/ig,
            ];
            for (const re of patterns) {
                let id;
                while ((id = re.exec(block)) !== null) ids.add(Number(id[1]));
            }
            for (const id of ids) addCandidate(id, 100, 'store_block_zero_or_100_percent');
        }
    } catch (err) {
        log('WARN', `Could not inspect Steam store page for free package: ${String(err?.message || err)}`);
    }

    try {
        const apiText = await fetchText(`https://store.steampowered.com/api/appdetails?appids=${appId}&cc=us&l=en`);
        const api = JSON.parse(apiText);
        const data = api?.[String(appId)]?.data;
        const price = data?.price_overview;
        // is_free alone describes normal F2P, not a 100%-off promotion. The
        // direct requestFreeLicense path already handles ordinary F2P games.
        const freePromotion = price && (Number(price.final) === 0 || Number(price.discount_percent) === 100);
        if (freePromotion) {
            for (const pkg of (Array.isArray(data?.packages) ? data.packages : [])) {
                addCandidate(pkg, 80, 'appdetails_final_zero');
            }
            for (const group of (Array.isArray(data?.package_groups) ? data.package_groups : [])) {
                for (const sub of (Array.isArray(group?.subs) ? group.subs : [])) {
                    const subZero = Number(sub?.price_in_cents_with_discount) === 0 || Number(sub?.percent_savings) === 100;
                    if (subZero && sub?.packageid != null) addCandidate(sub.packageid, 90, 'appdetails_package_zero');
                }
            }
        }
    } catch (err) {
        log('INFO', `Steam appdetails package discovery unavailable for ${appId}: ${String(err?.message || err)}`);
    }

    return [...candidates.values()].sort((a,b) => b.score-a.score).map(x => x.id);
}

function requestWebSession() {
    return new Promise((resolve, reject) => {
        const onWebSession = (sessionId, cookies) => {
            cleanup();
            resolve({sessionId, cookies});
        };
        const onError = err => { cleanup(); reject(err || new Error('Failed to establish web session')); };
        const cleanup = () => {
            client.removeListener('webSession', onWebSession);
            client.removeListener('error', onError);
        };
        client.once('webSession', onWebSession);
        client.once('error', onError);
        client.webLogOn();
    });
}

async function refreshStoreSessionId() {
    if (!webCookies.length) throw new Error('Steam web session cookies unavailable');
    try {
        const html = await fetchAuthenticatedText('https://store.steampowered.com/');
        const match = html.match(/g_sessionID\s*=\s*["']([^"']+)["']/i);
        if (match && match[1]) {
            webSessionId = match[1];
            log('INFO', 'Steam Store session ID refreshed from authenticated store page');
        }
    } catch (err) {
        log('WARN', `Could not refresh Steam Store session ID: ${String(err?.message || err)}`);
    }
    return webSessionId;
}

function sanitizeDiagnosticText(value, maxLen = 900) {
    let text = String(value || '');
    // Never log cookies, session IDs, refresh tokens, auth codes, or other
    // credential-like values even if Steam happens to echo them.
    text = text.replace(/(?:steamLoginSecure|sessionid|g_sessionID|refresh_token|access_token|shared_secret|identity_secret|password)\s*[=:]\s*[^&\s"'<>]+/ig, '$1=[REDACTED]');
    text = text.replace(/(?:^|[?&])(sessionid|steamLoginSecure|token|access_token|refresh_token)=[^&\s]+/ig, '$1=[REDACTED]');
    text = text.replace(/https?:\/\/[^\s"'<>]+/ig, '[URL]');
    text = text.replace(/\b[A-Za-z0-9_-]{40,}\b/g, '[LONG_TOKEN_REDACTED]');
    text = text.replace(/\s+/g, ' ').trim();
    return text.slice(0, maxLen);
}

function classifySteamStoreResponse(statusCode, location, body, json) {
    const text = String(body || '').toLowerCase();
    const loc = String(location || '').toLowerCase();
    const detail = json && json.purchaseresultdetail != null ? Number(json.purchaseresultdetail) : null;

    if (detail === 9 || /already\s+(owned|in your library|available)/i.test(body)) {
        return {code:'already_owned', reason:'Steam reports that the package is already owned.'};
    }
    if (/captcha|recaptcha|verify you are human/i.test(body)) {
        return {code:'captcha', reason:'Steam returned a CAPTCHA/human-verification response.'};
    }
    if (/login|signin|sign in|not logged/i.test(loc + ' ' + text)) {
        return {code:'not_authenticated', reason:'Steam redirected the request toward an authentication page.'};
    }
    if (/session.?id|invalid session|expired session|session has expired/i.test(text)) {
        return {code:'session_invalid', reason:'Steam response mentions an invalid or expired Store session.'};
    }
    if (/too many|rate.?limit|try again later|temporarily unavailable/i.test(text)) {
        return {code:'rate_limited', reason:'Steam indicates a temporary/rate-limit condition.'};
    }
    if (/must own|requires? .*game|need to own|cannot purchase|not eligible|not available for purchase|not available in your country|country|region/i.test(text)) {
        return {code:'eligibility', reason:'Steam response appears to indicate a purchase/ownership/region eligibility restriction.'};
    }
    if (/error_box|problem adding|problem occurred|failed|failure|error/i.test(text)) {
        return {code:'store_rejected', reason:'Steam returned an explicit store error/failure response.'};
    }
    if (statusCode === 302 || statusCode === 303) {
        if (/checkout\/addfreelicense/i.test(loc)) {
            return {code:'checkout_redirect', reason:'Steam redirected back to the free-license checkout endpoint without an explicit success response.'};
        }
        return {code:'redirect', reason:'Steam redirected the request without an explicit success response.'};
    }
    if (statusCode === 200) {
        return {code:'no_explicit_success', reason:'Steam returned HTTP 200 but no recognizable success marker was found.'};
    }
    return {code:'http_error', reason:`Steam returned HTTP ${statusCode}.`};
}

async function inspectPromoPackage(subId, appId) {
    const result = {subId:Number(subId), appId:Number(appId), statusCode:null, title:null, bodyPreview:null, hints:[]};
    try {
        const html = await fetchAuthenticatedText(`https://store.steampowered.com/sub/${subId}/?l=english`);
        result.statusCode = 200;
        const title = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
        if (title) result.title = sanitizeDiagnosticText(title[1], 180);

        const compact = html.replace(/<script[\s\S]*?<\/script>/ig, ' ')
            .replace(/<style[\s\S]*?<\/style>/ig, ' ')
            .replace(/<[^>]+>/g, ' ')
            .replace(/&nbsp;/ig, ' ')
            .replace(/\s+/g, ' ')
            .trim();
        const lower = compact.toLowerCase();
        const patterns = [
            ['requires_base_game', /must own|requires? .*game|need to own|requires? ownership|you must own/],
            ['not_available_region', /not available in your country|not available in your region|country.*restriction|region.*restriction/],
            ['already_owned', /already own|already in your library|already available/],
            ['free_promo', /free to keep|100% off|\$0\.00|add to account/],
            ['login_required', /sign in|log in/]
        ];
        for (const [code, re] of patterns) if (re.test(lower)) result.hints.push(code);
        result.bodyPreview = sanitizeDiagnosticText(compact, 700);
        log('INFO', `Promo package ${subId} page diagnostic: title=${JSON.stringify(result.title || '')}, hints=${result.hints.join(',') || 'none'}, preview=${JSON.stringify(result.bodyPreview || '')}`);
    } catch (err) {
        result.statusCode = null;
        result.hints.push('package_page_fetch_failed');
        log('WARN', `Promo package ${subId} page diagnostic failed: ${sanitizeDiagnosticText(err?.message || err, 300)}`);
    }
    return result;
}


function classifyEligibilitySignals(signals) {
    const has = code => signals.includes(code);
    if (has('already_owned')) return {code:'already_owned', reason:'Аккаунт уже имеет этот пакет/лицензию.'};
    if (has('requires_base_game')) return {code:'requires_base_game', reason:'Steam указывает, что для этого DLC/пакета требуется базовая игра.'};
    if (has('region_restricted')) return {code:'region_restricted', reason:'Steam указывает ограничение по стране/региону.'};
    if (has('not_eligible')) return {code:'not_eligible', reason:'Steam указывает, что аккаунт не соответствует условиям предложения.'};
    return {code:'eligible_unknown', reason:'Явного запрета Steam до запроса не обнаружено.'};
}

async function inspectAccountLicensesForPackage(subId) {
    const result = {subId:Number(subId), owned:false, signals:[]};
    try {
        const html = await fetchAuthenticatedText('https://store.steampowered.com/account/licenses/?l=english');
        const needle = String(subId);
        const patterns = [
            new RegExp('RemoveFreeLicense\\s*\\(\\s*' + needle + '\\b', 'i'),
            new RegExp('/sub/' + needle + '(?:\\D|$)', 'i'),
            new RegExp('(?:package|subid)[^\\n]{0,120}\\b' + needle + '\\b', 'i')
        ];
        if (patterns.some(re => re.test(html))) {
            result.owned = true;
            result.signals.push('already_owned');
        }
    } catch (err) {
        result.signals.push('license_page_unavailable');
        log('WARN', `Account license preflight for SubID ${subId} failed: ${sanitizeDiagnosticText(err?.message || err, 300)}`);
    }
    try {
        const licenses = Array.isArray(client.licenses) ? client.licenses : [];
        if (licenses.some(license => Number(license?.packageid) === Number(subId))) {
            result.owned = true;
            if (!result.signals.includes('already_owned')) result.signals.push('already_owned');
        }
    } catch (_) {}
    log('INFO', `Eligibility preflight SubID ${subId}: account_license=${result.owned ? 'owned' : 'not_owned'}; signals=${result.signals.join(',') || 'none'}`);
    return result;
}

async function inspectAppEligibility(appId, subId, packageDiagnostic) {
    const result = {appId:Number(appId), subId:Number(subId), signals:[], type:null, parentAppId:null, title:null};
    let appData = null;
    try {
        const apiText = await fetchText(`https://store.steampowered.com/api/appdetails?appids=${appId}&cc=us&l=en`);
        const api = JSON.parse(apiText);
        appData = api?.[String(appId)]?.data || null;
        if (appData) {
            result.type = String(appData.type || '').toLowerCase() || null;
            result.title = sanitizeDiagnosticText(appData.name || '', 180);
            const fullgame = appData.fullgame;
            if (fullgame?.appid != null) result.parentAppId = Number(fullgame.appid);
            if (result.type === 'dlc' && result.parentAppId) {
                // This is evidence of a parent game, not by itself proof of a
                // purchase restriction. A hard restriction must come from
                // Steam's own page/metadata.
                log('INFO', `Eligibility preflight AppID ${appId}: DLC parent AppID ${result.parentAppId} detected`);
            }
        }
    } catch (err) {
        log('INFO', `Eligibility AppDetails unavailable for AppID ${appId}: ${sanitizeDiagnosticText(err?.message || err, 300)}`);
    }

    const textParts = [];
    if (packageDiagnostic?.bodyPreview) textParts.push(packageDiagnostic.bodyPreview);
    if (packageDiagnostic?.title) textParts.push(packageDiagnostic.title);
    const text = textParts.join(' ').toLowerCase();

    if (/already own|already in your library|already available/.test(text)) result.signals.push('already_owned');
    if (/must own|you must own|requires? .*base game|requires? .*game|need to own|requires? ownership|owned.*required/.test(text)) result.signals.push('requires_base_game');
    if (/not available in your country|not available in your region|country restriction|region restriction|restricted country/.test(text)) result.signals.push('region_restricted');
    if (/not eligible|ineligible|does not qualify|not qualified|eligibility requirement/.test(text)) result.signals.push('not_eligible');

    if (result.signals.includes('already_owned') && !packageDiagnostic?.hints?.includes('already_owned')) packageDiagnostic?.hints?.push('already_owned');
    if (result.signals.includes('requires_base_game') && !packageDiagnostic?.hints?.includes('requires_base_game')) packageDiagnostic?.hints?.push('requires_base_game');
    if (result.signals.includes('region_restricted') && !packageDiagnostic?.hints?.includes('not_available_region')) packageDiagnostic?.hints?.push('not_available_region');

    const classification = classifyEligibilitySignals(result.signals);
    log('INFO', `Eligibility preflight SubID ${subId}: classification=${classification.code}; reason=${classification.reason}; app_type=${result.type || 'unknown'}; parent_appid=${result.parentAppId || 'none'}`);
    return {...result, classification};
}

async function preflightFreeLicense(subId, appId = null, packageDiagnostic = null) {
    const account = await inspectAccountLicensesForPackage(subId);
    if (account.owned) {
        return {ok:true, skipPost:true, code:'already_owned', reason:'Аккаунт уже имеет лицензию этого SubID.', account, eligibility:null};
    }

    const eligibility = appId ? await inspectAppEligibility(appId, subId, packageDiagnostic) : null;
    if (eligibility?.classification?.code && eligibility.classification.code !== 'eligible_unknown') {
        return {ok:false, skipPost:true, code:eligibility.classification.code, reason:eligibility.classification.reason, account, eligibility};
    }

    return {ok:true, skipPost:false, code:'eligible_unknown', reason:'Явного запрета до POST не найдено.', account, eligibility};
}

async function postAddFreeLicense(subId, appId = null) {
    if (!webSessionId || !webCookies.length) {
        throw new Error('Steam web session unavailable');
    }

    await refreshStoreSessionId();

    // Capture the package page before the POST. This gives us useful evidence
    // when Steam returns a redirect, without exposing any authenticated data.
    const packageDiagnostic = appId ? await inspectPromoPackage(subId, appId) : null;

    const preflight = await preflightFreeLicense(subId, appId, packageDiagnostic);
    if (preflight.code === 'already_owned') {
        log('INFO', `Eligibility decision SubID ${subId}: already_owned; POST skipped`);
        return {ok:true, alreadyOwned:true, responseConfirmed:true, licenseConfirmed:true, statusCode:null, location:'', body:'', diagnostic:{packageDiagnostic, preflight}};
    }
    if (preflight.skipPost) {
        log('INFO', `Eligibility decision SubID ${subId}: ${preflight.code}; POST skipped; reason=${preflight.reason}`);
        const err = new Error(`Steam eligibility preflight: ${preflight.code}; ${preflight.reason}`);
        err.diagnostic = {packageDiagnostic, preflight};
        throw err;
    }
    log('INFO', `Eligibility decision SubID ${subId}: ${preflight.code}; proceeding with Store POST`);

    const payload = querystring.stringify({
        action: 'add_to_cart',
        sessionid: webSessionId,
        subid: String(subId),
    });

    const path = `/checkout/addfreelicense/${encodeURIComponent(String(subId))}`;

    return new Promise((resolve, reject) => {
        const req = https.request({
            method: 'POST',
            hostname: 'store.steampowered.com',
            path,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Content-Length': Buffer.byteLength(payload),
                Cookie: cookieHeader(),
                Origin: 'https://store.steampowered.com',
                Referer: `https://store.steampowered.com/sub/${subId}/`,
                'X-Requested-With': 'XMLHttpRequest',
                Accept: 'application/json, text/javascript, */*; q=0.01',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/154.0 Safari/537.36'
            }
        }, response => {
            let body = '';
            response.setEncoding('utf8');
            response.on('data', chunk => body += chunk);
            response.on('end', async () => {
                const location = response.headers.location || '';
                let json = null;
                try { json = JSON.parse(body); } catch (_) {}

                const purchaseresultdetail = json && json.purchaseresultdetail != null
                    ? Number(json.purchaseresultdetail) : null;
                const jsonSuccess = json && typeof json.success === 'boolean'
                    ? json.success : null;
                const lower = body.toLowerCase();
                const alreadyOwned = purchaseresultdetail === 9 ||
                    lower.includes('already owned') || lower.includes('already in your library') ||
                    lower.includes('already available');
                const explicitSuccess = jsonSuccess === true ||
                    (Array.isArray(json) && json.length === 0) ||
                    lower.includes('add_free_content_success_area') ||
                    lower.includes('package has been added') ||
                    lower.includes('added to your account');

                const classification = classifySteamStoreResponse(response.statusCode, location, body, json);
                const bodyPreview = sanitizeDiagnosticText(body, 900);
                const headerNames = Object.keys(response.headers || {}).map(String).sort();

                log('INFO', `Free-license HTTP ${response.statusCode} for SubID ${subId}${location ? ` -> ${sanitizeDiagnosticText(location, 300)}` : ''}`);
                log('INFO', `Free-license diagnostic SubID ${subId}: classification=${classification.code}; reason=${classification.reason}`);
                log('INFO', `Free-license diagnostic SubID ${subId}: content-type=${String(response.headers['content-type'] || 'unknown')}; content-length=${String(response.headers['content-length'] || body.length)}; response-headers=${headerNames.join(',') || 'none'}`);
                log('INFO', `Free-license diagnostic SubID ${subId}: purchaseresultdetail=${purchaseresultdetail == null ? 'none' : purchaseresultdetail}; json_success=${jsonSuccess == null ? 'none' : jsonSuccess}; body-preview=${JSON.stringify(bodyPreview || '')}`);
                if (packageDiagnostic) {
                    log('INFO', `Free-license package context SubID ${subId}: page_hints=${packageDiagnostic.hints.join(',') || 'none'}`);
                }

                if (response.statusCode === 200 && (explicitSuccess || alreadyOwned)) {
                    resolve({ok:true, alreadyOwned, statusCode:response.statusCode, location, body, responseConfirmed:true, diagnostic:{classification, packageDiagnostic, preflight}});
                    return;
                }
                if ((response.statusCode === 302 || response.statusCode === 303) && alreadyOwned) {
                    resolve({ok:true, alreadyOwned:true, statusCode:response.statusCode, location, body, responseConfirmed:true, diagnostic:{classification, packageDiagnostic, preflight}});
                    return;
                }

                const error = new Error(`Steam free-license request was not confirmed: ${classification.code}; ${classification.reason}; HTTP ${response.statusCode}; Location: ${sanitizeDiagnosticText(location, 300) || '(none)'}; Body: ${bodyPreview || '(empty)'}`);
                error.diagnostic = {classification, packageDiagnostic, preflight, statusCode:response.statusCode, location:sanitizeDiagnosticText(location, 300), bodyPreview, purchaseresultdetail, jsonSuccess};
                reject(error);
            });
        });
        req.on('error', reject);
        req.setTimeout(20000, () => req.destroy(new Error('Steam free-license request timeout')));
        req.write(payload);
        req.end();
    });
}

function getOwnedApps() {
    return new Promise((resolve, reject) => {
        // getUserOwnedApps requires the account's games to be visible.
        client.getUserOwnedApps(steamId, {includePlayedFreeGames:true, includeFreeSub:true}, (err, response) => {
            if (err) return reject(err);
            const apps = Array.isArray(response?.apps) ? response.apps :
                (Array.isArray(response?.games) ? response.games : []);
            resolve(apps.map(game => ({
                appid: Number(game.appid),
                name: String(game.name || `App ${game.appid}`),
                playtime_forever: Number(game.playtime_forever || 0),
                playtime_2weeks: game.playtime_2weeks == null ? null : Number(game.playtime_2weeks),
                img_icon_url: game.img_icon_url || '',
                img_logo_url: game.img_logo_url || '',
                rtime_last_played: Number(game.rtime_last_played || 0)
            })).filter(game => Number.isInteger(game.appid) && game.appid > 0));
        });
    });
}

async function tryFreeStorePackages(appId) {
    let session;
    try {
        session = await requestWebSession();
        webSessionId = session.sessionId;
        webCookies = session.cookies || [];
    } catch (err) {
        log('WARN', `Could not create Steam web session for free-price fallback: ${String(err?.message || err)}`);
        return null;
    }

    const subIds = await discoverFreePromoSubIds(appId);
    log('INFO', `Found ${subIds.length} possible free/promotional SubID(s) for AppID ${appId}`);

    for (const subId of subIds) {
        try {
            log('INFO', `Trying free/promotional SubID ${subId} for AppID ${appId}`);
            const result = await postAddFreeLicense(subId, appId);
            if (result.ok) {
                const licenseConfirmed = result.alreadyOwned || result.responseConfirmed || await confirmStoreLicense(subId, 12000);
                if (licenseConfirmed) {
                    log('INFO', `SubID ${subId} confirmed in Steam account licenses for AppID ${appId}`);
                    return {subId, result, licenseConfirmed:true};
                }
                log('INFO', `SubID ${subId} returned a non-error response, but Steam account does not show the license; treating it as NOT added`);
                continue;
            }
        } catch (err) {
            log('INFO', `SubID ${subId} was not accepted: ${sanitizeDiagnosticText(err?.message || err, 1400)}`);
        }
    }
    return null;
}

async function confirmOwnedApp(appId, waitMs = 15000) {
    const deadline = Date.now() + waitMs;
    while (Date.now() < deadline) {
        try {
            if (typeof client.getOwnedApps === 'function') {
                const ids = client.getOwnedApps({excludeShared: true});
                if (Array.isArray(ids) && ids.map(Number).includes(Number(appId))) return true;
            }
        } catch (_) {}
        await delay(1000);
    }
    return false;
}

async function addTarget() {
    if (target.type === 'app') {
        let directError = null;

        try {
            log('INFO', `Requesting free license for AppID ${target.id}`);
            const result = await new Promise((resolve, reject) => {
                client.requestFreeLicense([target.id], (err, packageIds, appIds) => {
                    if (err) return reject(err);
                    const packages = Array.isArray(packageIds) ? packageIds : [];
                    const apps = Array.isArray(appIds) ? appIds : [];
                    resolve({packageIds: packages, appIds: apps});
                });
            });

            log('INFO', `Steam license response: packages=${result.packageIds.length}, apps=${result.appIds.length}`);
            log('INFO', `Granted AppIDs: ${result.appIds.join(',') || 'none'}`);
            log('INFO', `Granted PackageIDs: ${result.packageIds.join(',') || 'none'}`);

            // Steam may grant the package while not echoing the AppID.
            const added = result.appIds.includes(target.id) || result.packageIds.length > 0;
            if (added) {
                log('INFO', `License granted for AppID ${target.id}; waiting for Steam ownership cache sync`);
                const owned = await confirmOwnedApp(target.id, 15000);
                if (owned) {
                    log('INFO', `Ownership cache confirms AppID ${target.id}`);
                } else {
                    log('INFO', `Steam license for AppID ${target.id} is granted; owned-games API has not refreshed yet`);
                }

                finish({ok:true, action:'added', type:'app', appid:target.id,
                    owned_confirmed:owned,
                    message:`Игра ${target.id} добавлена в библиотеку`,
                    refresh_token:latestRefreshToken, auth_session_invalid:false});
                return;
            }
        } catch (err) {
            directError = err;
            log('INFO', `requestFreeLicense did not grant AppID ${target.id}: ${String(err?.message || err)}`);
        }

        // requestFreeLicense is intentionally limited to free-on-demand
        // licenses. Steam's own node-steam-user documentation says that
        // temporary promotional "free to keep" licenses need the Store's
        // add-free-license flow instead.
        log('INFO', `Checking Steam Store for a zero-price/free-to-keep package for ${target.id}`);
        try {
            const promo = await tryFreeStorePackages(target.id);
            if (promo) {
                const owned = await confirmOwnedApp(target.id, 10000);
                finish({ok:true, action:'added', type:'app', appid:target.id,
                    subid:promo.subId, owned_confirmed:owned, license_confirmed:promo.licenseConfirmed === true,
                    message:`Игра ${target.id} успешно добавилась`,
                    refresh_token:latestRefreshToken, auth_session_invalid:false});
                return;
            }
        } catch (promoErr) {
            log('WARN', `Zero-price Store fallback failed: ${String(promoErr?.message || promoErr)}`);
        }

        finish({ok:false, auth_session_invalid:false, action:'purchase_required', type:'app', appid:target.id,
            store_url:`https://store.steampowered.com/app/${target.id}/`,
            error: directError
                ? `Steam не выдал бесплатную лицензию: ${String(directError?.message || directError)}. Если на странице Steam цена 0.00 / -100% и есть «Add to Account», для такого предложения нужен бесплатный Store package.`
                : 'Steam не выдал бесплатную лицензию для этого AppID. Если на странице Steam цена 0.00 / -100% и есть «Add to Account», попробуйте ещё раз.'});
        return;
    }

    let session;
    try {
        session = await requestWebSession();
    } catch (err) {
        await delay(1500);
        try {
            session = await requestWebSession();
        } catch (retryErr) {
            finish({ok:false, auth_session_invalid:false, error:'Steam web session failed: ' + String(retryErr?.message || retryErr)});
            return;
        }
    }
    webSessionId = session.sessionId;
    webCookies = session.cookies || [];
    log('INFO', `Requesting free license for SubID ${target.id}`);
    try {
        const result = await postAddFreeLicense(target.id);
        if (result.ok) {
            const licenseConfirmed = result.alreadyOwned || result.responseConfirmed || result.licenseConfirmed || await confirmStoreLicense(target.id, 12000);
            if (licenseConfirmed) {
                finish({ok:true, action:'added', type:'sub', subid:target.id, license_confirmed:true, message:`Лицензия subid ${target.id} добавлена`, refresh_token:latestRefreshToken, auth_session_invalid:false});
            } else {
                finish({ok:false, auth_session_invalid:false, action:'purchase_required', type:'sub', subid:target.id,
                    store_url:`https://store.steampowered.com/sub/${target.id}/`,
                    error:'Steam не подтвердил наличие лицензии после запроса. Ничего не добавлено.'});
            }
        } else {
            finish({ok:false, auth_session_invalid:false, action:'purchase_required', type:'sub', subid:target.id,
                store_url:`https://store.steampowered.com/sub/${target.id}/`,
                error:'Steam не выдал бесплатную лицензию. Для платного набора откройте официальную страницу покупки.'});
        }
    } catch (err) {
        finish({ok:false, auth_session_invalid:false, action:'purchase_required', type:'sub', subid:target.id,
            store_url:`https://store.steampowered.com/sub/${target.id}/`,
            error:String(err?.message || err)});
    }
}

client.once('loggedOn', async () => {
    try {
        log('INFO', `Steam login accepted for ${login}`);
        if (command === 'list') {
            const apps = await getOwnedApps();
            finish({ok:true, action:'list', steamid:steamId, games:apps, count:apps.length, refresh_token:latestRefreshToken, auth_session_invalid:false});
            return;
        }
        await addTarget();
    } catch (err) {
        finish({ok:false, error:String(err?.message || err)});
    }
});

client.on('error', err => {
    if (!finished) finish({ok:false, auth_session_invalid:usingSavedSession && !client.steamID, error:String(err?.message || err)});
});
client.on('disconnected', (eresult, msg) => {
    if (!finished) finish({ok:false, auth_session_invalid:usingSavedSession && !client.steamID, error:`Steam disconnected: ${msg || eresult}`});
});

try {
    if (refreshToken) {
        log('INFO', 'Connecting to Steam using saved encrypted session');
        client.logOn({refreshToken, steamID:steamId, machineName:`account_manager_games_${login}`});
    } else {
        const code = SteamTotp.getAuthCode(sharedSecret);
        client.logOn({accountName:login, password, twoFactorCode:code, machineName:`account_manager_games_${login}`});
    }
} catch (err) {
    finish({ok:false, error:String(err?.message || err)});
}

setTimeout(() => {
    if (!finished) finish({ok:false, error:'Steam games helper timeout'});
}, 45000);
