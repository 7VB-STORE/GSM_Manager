
const SteamUser = require('steam-user');
const SteamTotp = require('steam-totp');
const https = require('https');

const login = process.env.SHARK_STEAM_LOGIN || '';
const password = process.env.SHARK_STEAM_PASSWORD || '';
const sharedSecret = process.env.SHARK_STEAM_SHARED_SECRET || '';
const steamId = process.env.SHARK_STEAM_ID || '';
const refreshToken = process.env.SHARK_STEAM_REFRESH_TOKEN || '';

function out(obj) {
    try { process.stdout.write(JSON.stringify(obj) + '\n'); } catch (_) {}
}
function log(level, message) { out({type:'log', level, message:String(message || '')}); }
function fail(message) { finish({ok:false,error:String(message || 'Unknown error')}); }

if (!login || !steamId || (!refreshToken && (!password || !sharedSecret))) {
    fail('Missing Steam authorization data');
    process.exit(2);
}

const client = new SteamUser({enablePicsCache:true, renewRefreshTokens:false});
let finished = false;
let webCookies = [];
let walletState = null;
let webSessionReceived = false;
let walletEventReceived = false;
let webSessionProcessing = false;
let latestRefreshToken = refreshToken || '';

client.on('refreshToken', token => {
    if (token) latestRefreshToken = String(token);
    log('INFO', 'Steam refresh token received/renewed');
});

const CURRENCY = {
    1:'USD',2:'GBP',3:'EUR',4:'CHF',5:'RUB',6:'PLN',7:'BRL',8:'JPY',9:'NOK',10:'IDR',
    11:'MYR',12:'PHP',13:'SGD',14:'THB',15:'VND',16:'KRW',17:'TRY',18:'UAH',19:'MXN',
    20:'CAD',21:'AUD',22:'NZD',23:'CNY',24:'INR',25:'CLP',26:'PEN',27:'COP',28:'ZAR',
    29:'HKD',30:'TWD',31:'SAR',32:'AED',33:'SEK',34:'ARS',35:'ILS',36:'BYN',37:'KZT',
    38:'KWD',39:'QAR',40:'CRC',41:'UYU',42:'BGN',43:'HRK',44:'CZK',45:'DKK',46:'HUF',47:'RON'
};
const SYMBOL = {
    USD:'$',GBP:'£',EUR:'€',CHF:'CHF ',RUB:'₽',PLN:'zł',BRL:'R$',JPY:'¥',NOK:'kr',IDR:'Rp',
    MYR:'RM',PHP:'₱',SGD:'S$',THB:'฿',VND:'₫',KRW:'₩',TRY:'₺',UAH:'₴',MXN:'MX$',CAD:'C$',
    AUD:'A$',NZD:'NZ$',CNY:'¥',INR:'₹',CLP:'CLP',PEN:'S/',COP:'COP',ZAR:'R',HKD:'HK$',TWD:'NT$',
    SAR:'﷼',AED:'د.إ',SEK:'kr',ARS:'AR$',ILS:'₪',BYN:'Br',KZT:'₸',KWD:'د.ك',QAR:'﷼',CRC:'₡',
    UYU:'$U',BGN:'лв',HRK:'kn',CZK:'Kč',DKK:'kr',HUF:'Ft',RON:'lei'
};

function currencyCode(value) {
    if (typeof value === 'string' && /^[A-Za-z]{3}$/.test(value.trim())) return value.trim().toUpperCase();
    return CURRENCY[Number(value)] || String(value || '').trim().toUpperCase();
}
function formatWallet(balance, currency, alreadyMajor=false) {
    const code = currencyCode(currency);
    const n = Number(balance);
    if (!Number.isFinite(n)) return '';

    // g_rgWalletInfo.wallet_balance is in the smallest unit (e.g. cents).
    // The steam-user `wallet` event, however, already exposes the balance
    // divided by 100. Never divide an event balance twice.
    const amount = alreadyMajor ? n : (n / 100);
    let text = amount.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ' ');
    text = text.replace(/\.00$/, '');

    // Keep the stored value ASCII-safe and let the browser render the native
    // symbol. This avoids Windows console/code-page corruption of symbols
    // such as ₸, ₽, ₴ and ₩.
    return text + (code ? ' ' + code : '');
}

function finish(result) {
    if (finished) return;
    finished = true;
    try { client.logOff(); } catch (_) {}
    out(result);
    setTimeout(() => process.exit(result.ok ? 0 : 1), 250);
}

function fetchUrl(url, headers = {}, redirectDepth = 0) {
    return new Promise((resolve) => {
        log('INFO', 'GET ' + url);
        const req = https.get(url, {
            timeout: 15000,
            headers: Object.assign({
                'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/154.0 Safari/537.36',
                'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language':'en-US,en;q=0.9'
            }, headers)
        }, (res) => {
            const status = res.statusCode || 0;
            log(status >= 400 ? 'WARN' : 'INFO', 'Steam HTTP ' + status + ' for ' + url);

            if ([301,302,303,307,308].includes(status) && res.headers.location && redirectDepth < 5) {
                const nextUrl = new URL(res.headers.location, url).toString();
                log('INFO', 'Following Steam redirect to ' + nextUrl);
                res.resume();
                fetchUrl(nextUrl, headers, redirectDepth + 1).then(resolve);
                return;
            }

            if (!res || status >= 400) {
                if (res) res.resume();
                resolve({html:'',status,headers:res ? res.headers : {}});
                return;
            }

            let body = '';
            res.setEncoding('utf8');
            res.on('data', c => body += c);
            res.on('end', () => {
                log('INFO', 'Received ' + body.length + ' bytes from ' + url);
                resolve({html:body,status,headers:res.headers});
            });
        });
        req.on('error', e => { log('ERROR', 'HTTP request failed: ' + (e.message || e)); resolve({html:'',status:0,error:String(e.message || e)}); });
        req.on('timeout', () => { req.destroy(); log('ERROR', 'HTTP timeout: ' + url); resolve({html:'',status:0,error:'timeout'}); });
    });
}

function cookieHeader() { return webCookies.join('; '); }

function extractLevelXp(html) {
    const source = String(html || '');
    const rankMatch = source.match(/CS:GO Profile Rank:\s*([^\n<]+)/i);
    const xpMatch = source.match(/Experience points earned towards next rank:\s*([^\n<]+)/i);
    if (rankMatch && xpMatch) {
        const level = Number(rankMatch[1].trim().replace(/[,\s]/g, ''));
        const xp = Number(xpMatch[1].trim().replace(/,/g, '').split(/\s+/)[0]);
        if (Number.isInteger(level) && level >= 0 && Number.isInteger(xp) && xp >= 0) return {level, xp};
    }
    const rankJson = source.match(/"profile_rank"\s*:\s*(\d+)/i);
    if (rankJson) {
        const level = Number(rankJson[1]);
        if (Number.isInteger(level) && level >= 0) return {level, xp:0};
    }
    return {level:null, xp:null};
}

function extractCardGames(html) {
    const source=String(html||''), rows=source.split(/<div class="badge_row is_link/gi).slice(1), result=[];
    function clean(v){return String(v||'').replace(/<[^>]*>/g,' ').replace(/&nbsp;/g,' ').replace(/&amp;/g,'&').replace(/\s+/g,' ').replace(/View details/gi,'').trim();}
    for(const row of rows){
        const link=row.match(/gamecards\/(\d+)/i);
        const remaining=row.match(/(\d+)\s+card drops?\s+remaining/i);
        if(!link||!remaining)continue;
        const count=Number(remaining[1]);if(!Number.isInteger(count)||count<=0)continue;
        const title=row.match(/<div class="badge_title">([\s\S]*?)<\/div>/i);
        result.push({appid:Number(link[1]),name:clean(title?title[1]:'')||('App '+link[1]),cards_remaining:count});
    }
    return result;
}

function extractAvatar(html) {
    const m = html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i)
        || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["']/i);
    return m ? m[1].replace(/&amp;/g, '&') : '';
}

function extractWalletFromHtml(html) {
    if (typeof html !== 'string' || !html.trim()) return {formatted:'', currency:'', country:'', source:'', rawBalance:null};

    // Steam commonly exposes the wallet as:
    // var g_rgWalletInfo = {"wallet_currency":1,"wallet_country":"US","wallet_balance":"52",...};
    // It may also be declared with const/let or split across whitespace/newlines.
    const walletPatterns = [
        /(?:var|let|const)\s+g_rgWalletInfo\s*=\s*(\{[\s\S]*?\})\s*;/i,
        /g_rgWalletInfo\s*=\s*(\{[\s\S]*?\})\s*;/i
    ];

    for (const re of walletPatterns) {
        const m = html.match(re);
        if (!m) continue;
        try {
            const obj = JSON.parse(m[1]);
            const rawBalance = obj.wallet_balance ?? obj.wallet_delayed_balance ?? null;
            const numericBalance = Number(rawBalance);
            const cur = currencyCode(obj.wallet_currency);
            const country = String(obj.wallet_country || '');

            log('INFO', 'Parsed g_rgWalletInfo: currency=' + cur + ', country=' + country + ', rawBalance=' + String(rawBalance));

            if (Number.isFinite(numericBalance)) {
                const formatted = formatWallet(numericBalance, cur);
                if (formatted) {
                    return {formatted, currency:cur, country, source:'g_rgWalletInfo', rawBalance:numericBalance};
                }
            }
        } catch (e) {
            log('WARN', 'g_rgWalletInfo JSON parse failed: ' + String(e.message || e));
        }
    }

    const visibleWalletPatterns = [
        /id=["'](?:marketWalletBalanceAmount|header_wallet_balance)["'][^>]*>([\s\S]*?)<\/[^>]+>/i
    ];
    for (const re of visibleWalletPatterns) {
        const m = html.match(re);
        if (!m) continue;
        const text = m[1].replace(/<[^>]+>/g,' ')
            .replace(/&nbsp;/gi,' ').replace(/&amp;/g,'&')
            .replace(/&#36;/g,'$').replace(/&#8364;/g,'€').replace(/&#163;/g,'£')
            .replace(/&#82;/g,'R').replace(/\s+/g,' ').trim();
        const money = text.match(/(?:R\$|[$€£¥₽₴₸₩₹]|zł|CHF|kr|C\$|A\$|NZ\$|MX\$|S\$|₱|฿|₫|₺)\s*[+-]?\d+(?:[.,]\d{1,2})?(?:\s*(?:USD|EUR|GBP|CHF|RUB|PLN|BRL|JPY|NOK|SEK|IDR|MYR|PHP|SGD|THB|VND|KRW|TRY|UAH|MXN|CAD|AUD|NZD|CNY|INR|KZT|DKK|CZK|HUF|RON|ISK))?/i);
        if (money) return {formatted:money[0].replace(/\s+/g,' ').trim(),currency:'',country:'',source:'visible-wallet',rawBalance:null};
    }

    const clean = html
        .replace(/<script[\s\S]*?<\/script>/gi, ' ')
        .replace(/<style[\s\S]*?<\/style>/gi, ' ')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&nbsp;/gi, ' ')
        .replace(/&amp;/gi, '&')
        .replace(/&#36;/g, '$').replace(/&#8364;/g, '€').replace(/&#163;/g, '£')
        .replace(/\s+/g, ' ').trim();

    const marker = clean.match(/(?:Баланс\s+кошелька|Wallet\s+Balance|Steam\s+Wallet|Current\s+balance|Wallet)/i);
    const scope = marker && marker.index !== undefined ? clean.slice(marker.index, marker.index + 500) : clean;
    const money = /(?:[$€£¥₽₴₸₩₹]|(?:USD|EUR|GBP|CHF|RUB|PLN|BRL|JPY|NOK|SEK|IDR|MYR|PHP|SGD|THB|VND|KRW|TRY|UAH|MXN|CAD|AUD|NZD|CNY|INR|KZT|DKK|CZK|HUF|RON|ISK)\b)\s*[+-]?\s*\d+(?:[.,]\d{1,2})?\s*(?:USD|EUR|GBP|CHF|RUB|PLN|BRL|JPY|NOK|SEK|IDR|MYR|PHP|SGD|THB|VND|KRW|TRY|UAH|MXN|CAD|AUD|NZD|CNY|INR|KZT|DKK|CZK|HUF|RON|ISK)?/i;
    const match = scope.match(money);
    if (match) return {formatted:match[0].replace(/\s+/g,' ').trim(), currency:'', country:'', source:'page-text', rawBalance:null};
    return {formatted:'', currency:'', country:'', source:'', rawBalance:null};
}

function decodeHtml(value) {
    return String(value || '')
        .replace(/<br\s*\/?>/gi, ' ')
        .replace(/<[^>]*>/g, ' ')
        .replace(/&nbsp;/gi, ' ')
        .replace(/&amp;/gi, '&').replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'")
        .replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
        .replace(/&#(\d+);/g, (_, n) => { try { return String.fromCodePoint(Number(n)); } catch (_) { return ''; } })
        .replace(/&#x([0-9a-f]+);/gi, (_, n) => { try { return String.fromCodePoint(parseInt(n, 16)); } catch (_) { return ''; } })
        .replace(/\s+/g, ' ').trim();
}
function parseMinutes(text) {
    const s = decodeHtml(text).toLowerCase(); let total = 0;
    const h = s.match(/([\d.,]+)\s*(?:hrs?|hours?)/i); const m = s.match(/([\d.,]+)\s*(?:mins?|minutes?)/i);
    if (h) total += parseFloat(h[1].replace(',', '.')) * 60; if (m) total += parseFloat(m[1].replace(',', '.'));
    return Number.isFinite(total) ? Math.round(total) : 0;
}
function extractBalancedJson(source, marker) {
    const text = String(source || '');
    const start = text.indexOf(marker);
    if (start < 0) return null;
    let i = start + marker.length;
    while (i < text.length && /\s/.test(text[i])) i++;
    if (text[i] !== '[' && text[i] !== '{') return null;
    const open = text[i], close = open === '[' ? ']' : '}';
    let depth = 0, quote = false, escape = false;
    for (; i < text.length; i++) {
        const ch = text[i];
        if (quote) {
            if (escape) escape = false;
            else if (ch === '\\') escape = true;
            else if (ch === '"') quote = false;
            continue;
        }
        if (ch === '"') { quote = true; continue; }
        if (ch === open) depth++;
        else if (ch === close) {
            depth--;
            if (depth === 0) return text.slice(start + marker.length, i + 1).trim();
        }
    }
    return null;
}
function normalizeCommunityGame(g) {
    const appid = Number(g.appid ?? g.appID ?? g.appId ?? g.id ?? 0);
    if (!Number.isInteger(appid) || appid <= 0) return null;
    const name = decodeHtml(g.name || g.title || '') || `App ${appid}`;
    let minutes = NaN;
    const minuteValue = g.playtime_forever ?? g.playtimeForever ?? g.playtime_minutes;
    if (minuteValue !== undefined && minuteValue !== null && minuteValue !== '') minutes = Number(minuteValue);
    if (!Number.isFinite(minutes)) {
        const hourValue = g.hoursOnRecord ?? g.hours_forever ?? g.hoursForever ?? g.hours_played ?? g.hours;
        if (hourValue !== undefined && hourValue !== null && hourValue !== '') { const n = Number(hourValue); if (Number.isFinite(n)) minutes = n * 60; }
    }
    if (!Number.isFinite(minutes) && typeof g.playtime === 'string') {
        const pm = g.playtime.replace(',', '.').match(/([\d.]+)\s*(hours?|hrs?|h|minutes?|mins?|m)?/i);
        if (pm) { const n = Number(pm[1]); minutes = /^(hours?|hrs?|h)$/i.test(pm[2] || '') ? n * 60 : n; }
    }
    if (!Number.isFinite(minutes)) minutes = 0;
    let icon = g.img_icon_url || g.icon || g.logo || g.img || '';
    let logo = g.img_logo_url || g.logo_url || '';
    if (icon && !/^https?:\/\//i.test(icon) && !/^\/\//.test(icon)) icon = `https://media.steampowered.com/steamcommunity/public/images/apps/${appid}/${icon}.jpg`;
    if (logo && !/^https?:\/\//i.test(logo) && !/^\/\//.test(logo)) logo = `https://media.steampowered.com/steamcommunity/public/images/apps/${appid}/${logo}.jpg`;
    if (icon && /^\/\//.test(icon)) icon = 'https:' + icon;
    if (icon && /^\//.test(icon)) icon = 'https://steamcommunity.com' + icon;
    if (logo && /^\/\//.test(logo)) logo = 'https:' + logo;
    if (logo && /^\//.test(logo)) logo = 'https://steamcommunity.com' + logo;
    return {appid,name,playtime_forever:Math.round(minutes),playtime_2weeks:g.playtime_2weeks == null ? null : Number(g.playtime_2weeks),img_icon_url:icon,img_logo_url:logo,rtime_last_played:Number(g.rtime_last_played || 0)};
}

function parseEmbeddedGameData(html) {
    const source = String(html || '');
    const markers = ['var g_rgGameData =', 'var g_rgGameData=', 'g_rgGameData ='];
    let raw = null;
    for (const marker of markers) { raw = extractBalancedJson(source, marker); if (raw) break; }
    if (!raw) return [];
    try {
        const data = JSON.parse(raw);
        const arr = Array.isArray(data) ? data : Object.entries(data || {}).map(([key, value]) => ({...(value || {}), appid: value?.appid ?? value?.appID ?? key}));
        return arr.map(normalizeCommunityGame).filter(Boolean);
    } catch (e) {
        log('WARN', 'g_rgGameData JSON parse failed: ' + String(e.message || e));
        return [];
    }
}

function parseRgGames(html) {
    const raw = extractBalancedJson(String(html || ''), 'var rgGames =');
    if (!raw) return [];
    try {
        const data = JSON.parse(raw);
        const arr = Array.isArray(data) ? data : Object.values(data || {});
        return arr.map(normalizeCommunityGame).filter(Boolean);
    } catch (_) { return []; }
}
function parseCommunityXml(xml) {
    const source = String(xml || ''), games = new Map();
    const re = /<game>([\s\S]*?)<\/game>/gi; let m;
    const tag = (block, name) => { const x = block.match(new RegExp(`<${name}[^>]*>([\s\S]*?)<\/${name}>`, 'i')); return x ? decodeHtml(x[1]) : ''; };
    while ((m = re.exec(source)) !== null) {
        const block = m[1], appid = Number(tag(block, 'appID'));
        if (!Number.isInteger(appid) || appid <= 0) continue;
        const hours = Number(tag(block, 'hoursOnRecord'));
        const mins = Number.isFinite(hours) ? hours * 60 : 0;
        let logo = tag(block, 'logo');
        if (logo && !/^https?:\/\//i.test(logo)) logo = `https://media.steampowered.com/steamcommunity/public/images/apps/${appid}/${logo}.jpg`;
        games.set(appid,{appid,name:tag(block,'name') || `App ${appid}`,playtime_forever:Math.round(mins),playtime_2weeks:null,img_icon_url:logo,img_logo_url:logo,rtime_last_played:0});
    }
    return Array.from(games.values());
}

function parseCommunityGames(html) {
    const source = String(html || ''); const games = new Map(); let match;
    // Big Picture markup exposes the account's game library as g_rgGameData.
    // Prefer it because it can contain the complete library even when the
    // normal page renders only a limited first batch.
    const bpGames = parseEmbeddedGameData(source);
    for (const g of bpGames) games.set(g.appid, g);
    // The normal Community page may also expose the library as rgGames.
    const embedded = parseRgGames(source);
    for (const g of embedded) {
        const old = games.get(g.appid);
        games.set(g.appid, {
            ...(old || {}), ...(g || {}),
            playtime_forever: Math.max(Number(old?.playtime_forever || 0), Number(g.playtime_forever || 0)),
            img_icon_url: g.img_icon_url || old?.img_icon_url || '',
            img_logo_url: g.img_logo_url || old?.img_logo_url || ''
        });
    }
    const rowRe = /<div[^>]*class=["'][^"']*\bgameListRow\b[^"']*["'][^>]*>[\s\S]*?(?=<div[^>]*class=["'][^"']*\bgameListRow\b|<\/body|$)/gi;
    while ((match = rowRe.exec(source)) !== null) {
        const row = match[0];
        const idMatch = row.match(/\bid=["']game_(\d+)["']/i) || row.match(/\bdata-appid=["'](\d+)["']/i) || row.match(/\/app\/(\d+)/i);
        if (!idMatch) continue; const appid = Number(idMatch[1]); if (!Number.isInteger(appid) || appid <= 0) continue;
        const nameMatch = row.match(/<[^>]+class=["'][^"']*\bgameListRowItemName\b[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/i);
        const hoursMatch = row.match(/<[^>]+class=["'][^"']*\bgameListRowItemHours\b[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/i);
        const imgMatch = row.match(/<img[^>]+src=["']([^"']+)["'][^>]*>/i);
        let icon = imgMatch ? imgMatch[1] : ''; if (icon.startsWith('//')) icon = 'https:' + icon;
        games.set(appid, {appid, name:decodeHtml(nameMatch ? nameMatch[1] : '') || `App ${appid}`, playtime_forever:parseMinutes(hoursMatch ? hoursMatch[1] : ''), playtime_2weeks:null, img_icon_url:icon, img_logo_url:'', rtime_last_played:0});
    }
    // Newer Steam markup may use gameslistitems_GameName_* classes. Capture the nearest app link/card.
    if (!games.size) {
        const blocks = source.match(/<[^>]+class=["'][^"']*gameslistitems_[^"']*["'][^>]*>[\s\S]*?(?=<[^>]+class=["'][^"']*gameslistitems_|<\/body|$)/gi) || [];
        for (const block of blocks) {
            const idMatch = block.match(/(?:\/app\/|data-appid=["'])(\d+)/i); if (!idMatch) continue;
            const appid = Number(idMatch[1]); if (!Number.isInteger(appid) || appid <= 0) continue;
            const nm = block.match(/class=["'][^"']*gameslistitems_GameName_[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/i);
            const name = decodeHtml(nm ? nm[1] : ''); if (!name) continue;
            games.set(appid,{appid,name,playtime_forever:parseMinutes(block),playtime_2weeks:null,img_icon_url:'',img_logo_url:'',rtime_last_played:0});
        }
    }
    // Do NOT scan arbitrary /app/<id> links from the whole page. The Steam
    // page contains recommendations/featured content too, and that can make
    // unrelated games appear in the account library.
    return Array.from(games.values()).sort((a,b)=>String(a.name).localeCompare(String(b.name),undefined,{sensitivity:'base'}));
}

function getSteamOwnedGamesFromClient() {
    return new Promise((resolve) => {
        try {
            if (typeof client.getUserOwnedApps !== 'function') {
                resolve({games:[], count:0, ok:false, source:'client-api-unavailable'});
                return;
            }
            client.getUserOwnedApps(steamId, {
                includePlayedFreeGames: true,
                includeFreeSub: true,
                includeAppInfo: true,
                skipUnvettedApps: false
            }, (err, response) => {
                if (err || !response) {
                    log('WARN', 'Steam owned-games API failed: ' + String(err && (err.message || err) || 'empty response'));
                    resolve({games:[], count:0, ok:false, source:'client-api'});
                    return;
                }
                const raw = Array.isArray(response.games) ? response.games : (Array.isArray(response.apps) ? response.apps : []);
                const games = raw.map(normalizeCommunityGame).filter(Boolean);
                const count = Number(response.game_count ?? response.app_count);
                log('INFO', 'Steam owned-games API: ' + games.length + ' games, reported count=' + (Number.isFinite(count) ? count : 'n/a'));
                resolve({games, count:Number.isFinite(count) && count >= 0 ? Math.max(count, games.length) : games.length, ok:true, source:'client-api'});
            });
        } catch (e) {
            log('WARN', 'Steam owned-games API exception: ' + String(e.message || e));
            resolve({games:[], count:0, ok:false, source:'client-api-exception'});
        }
    });
}

function getSteamOwnedAppIds() {
    return new Promise((resolve) => {
        try {
            if (typeof client.getOwnedApps !== 'function') { resolve(new Set()); return; }
            const finishOwnership = () => {
                try {
                    const ids = client.getOwnedApps({excludeShared: true});
                    resolve(new Set((Array.isArray(ids) ? ids : []).map(Number).filter(n => Number.isInteger(n) && n > 0)));
                } catch (_) { resolve(new Set()); }
            };
            if (ownershipReadyDone) finishOwnership();
            else ownershipReady.then(finishOwnership).catch(() => resolve(new Set()));
        } catch (_) { resolve(new Set()); }
    });
}
function extractDisplayedGameCount(html) {
    const source = String(html || '');
    const patterns = [
        /profile_count_link_total[^>]*>\s*([\d,\.]+)/i,
        /profile_count_link[^>]*>\s*<[^>]*>\s*([\d,\.]+)\s*<\/[^>]+>\s*<[^>]*>\s*Games/i,
        /(?:^|[>\s])Games\s*<[^>]*>\s*([\d,\.]+)/i
    ];
    for (const re of patterns) {
        const m = source.match(re);
        if (m) {
            const n = Number(String(m[1]).replace(/[,.]/g, ''));
            if (Number.isInteger(n) && n >= 0) return n;
        }
    }
    return null;
}
async function scrapeCommunityGames(headers) {
    const url = `https://steamcommunity.com/profiles/${steamId}/games/?tab=all&l=english`;
    log('INFO', 'Steam Community: opening Games -> All Games page');

    const page = await fetchUrl(url, headers);
    if (page.status !== 200 || !page.html) {
        log('WARN','Steam Community games page HTTP '+page.status);
        return {games:[], count:0, ok:false};
    }

    // The Community Games -> All Games page is the authoritative source for
    // whether this account actually has games. Steam's client license list can
    // contain free/default/shared/tool licenses that are NOT shown as games on
    // the profile. In particular, a fresh account can have dozens of such
    // licenses while its Games page correctly says 0 games.
    const displayedCount = extractDisplayedGameCount(page.html);
    const explicitEmpty = /(?:you\s+have\s+no\s+games|this\s+profile\s+has\s+no\s+games|no\s+games\s+to\s+display|games\s*\(\s*0\s*\))/i.test(
        decodeHtml(String(page.html || '').replace(/<script[\s\S]*?<\/script>/gi,' '))
    );
    if (displayedCount === 0 || explicitEmpty) {
        log('INFO', 'Steam Community Games page confirms 0 games for SteamID ' + steamId + '; ignoring client license/app lists');
        return {games:[], count:0, ok:true, source:'community-empty'};
    }

    // Only after confirming that the Community Games page is non-empty do we
    // use the Steam client API to enrich the exact owned AppIDs. This prevents
    // free/default/shared licenses from becoming fake games.
    const ownedIds = await getSteamOwnedAppIds();
    const apiResult = await getSteamOwnedGamesFromClient();

    const byId = new Map();
    const mergeGame = (g) => {
        if (!g || !Number.isInteger(Number(g.appid)) || Number(g.appid) <= 0) return;
        const id = Number(g.appid);
        if (ownedIds.size && !ownedIds.has(id)) return;
        const old = byId.get(id);
        const oldMinutes = Number(old?.playtime_forever || 0);
        const newMinutes = Number(g.playtime_forever || 0);
        byId.set(id, {
            ...(old || {}), ...(g || {}), appid:id,
            name: (g.name && !/^App \d+$/.test(String(g.name))) ? g.name : (old?.name || g.name || `App ${id}`),
            playtime_forever: Math.max(Number.isFinite(oldMinutes) ? oldMinutes : 0, Number.isFinite(newMinutes) ? newMinutes : 0),
            img_icon_url: g.img_icon_url || old?.img_icon_url || '',
            img_logo_url: g.img_logo_url || old?.img_logo_url || ''
        });
    };

    // The Steam client API is the primary source for the current account's
    // library, names, icons and lifetime playtime. It is tied to the exact
    // logged-in SteamID, so it cannot return another account's library.
    for (const g of apiResult.games) mergeGame(g);

    // Community page is used as a second source for games that the API may not
    // enrich, and especially for hoursOnRecord. Only structured library data is
    // accepted; arbitrary store links are intentionally ignored.
    for (const g of parseEmbeddedGameData(page.html)) mergeGame(g);
    for (const g of parseRgGames(page.html)) mergeGame(g);
    for (const g of parseCommunityGames(page.html)) mergeGame(g);

    try {
        const xmlPage = await fetchUrl(url + '&xml=1', headers);
        if (xmlPage.status === 200 && xmlPage.html) {
            const xmlGames = parseCommunityXml(xmlPage.html);
            for (const x of xmlGames) mergeGame(x);
            log('INFO','Steam Community XML: распознано '+xmlGames.length+' игр; итоговая библиотека '+byId.size);
        } else {
            log('WARN','Steam Community XML HTTP '+xmlPage.status);
        }
    } catch (e) { log('WARN','Steam Community XML failed: '+String(e.message || e)); }

    // Big Picture can expose a more complete embedded game object list.
    try {
        const bpHeaders = {...headers, 'X-ValveUserAgent':'panorama'};
        const bp = await fetchUrl(url, bpHeaders);
        if (bp.status === 200 && bp.html) {
            const bpGames = parseEmbeddedGameData(bp.html);
            for (const g of bpGames) mergeGame(g);
            log('INFO','Steam Big Picture: распознано '+bpGames.length+' игр; итоговая библиотека '+byId.size);
        } else {
            log('WARN','Steam Big Picture games page HTTP '+bp.status);
        }
    } catch (e) { log('WARN','Steam Big Picture scrape failed: '+String(e.message || e)); }

    let games = Array.from(byId.values()).filter(g => Number.isInteger(Number(g.appid)) && Number(g.appid) > 0);

    // If the client API succeeded and returned games, its list is authoritative.
    // Community data is only allowed to enrich those exact AppIDs.
    if (apiResult.ok && apiResult.games.length) {
        const authoritative = new Map(apiResult.games.map(g => [Number(g.appid), g]));
        games = games.filter(g => authoritative.has(Number(g.appid)));
        for (const g of games) {
            const a = authoritative.get(Number(g.appid));
            if (Number(a.playtime_forever || 0) > Number(g.playtime_forever || 0)) g.playtime_forever = Number(a.playtime_forever);
            if (!g.name || /^App \d+$/.test(String(g.name))) g.name = a.name;
            if (!g.img_icon_url) g.img_icon_url = a.img_icon_url || '';
            if (!g.img_logo_url) g.img_logo_url = a.img_logo_url || '';
        }
        // Include API games that were not present in Community HTML.
        for (const a of apiResult.games) {
            const id = Number(a.appid);
            if (!games.some(g => Number(g.appid) === id)) games.push(a);
        }
    }

    games.sort((a,b)=>String(a.name||'').localeCompare(String(b.name||''),undefined,{sensitivity:'base'}));
    const count = games.length;
    // Never use response.game_count/app_count here: those can count licenses
    // which are not games displayed in the account's Games -> All Games page.
    log('INFO','Steam library final: '+count+' unique games confirmed for SteamID '+steamId);
    return {games, count, ok:true, source:'community-confirmed'};
}

client.on('loggedOn', () => {
    log('INFO', 'Steam client login accepted by Steam');
    log('INFO', 'SteamID: ' + steamId);
    if (client.wallet) log('INFO', 'Steam wallet object available after logon');
    try { client.setPersona(SteamUser.EPersonaState.Online); } catch (_) {}
    log('INFO', 'Waiting for Steam webSession event');
});

client.on('wallet', (hasWallet, currency, balance) => {
    walletEventReceived = true;
    walletState = {hasWallet:!!hasWallet, currency:currencyCode(currency), balance:Number(balance || 0)};
    log('INFO', 'Wallet event: hasWallet=' + !!hasWallet + ', currency=' + currencyCode(currency) + ', rawBalance=' + String(balance));
});

client.on('webSession', async (_sessionId, cookies) => {
    if (webSessionProcessing || finished) {
        log('INFO', 'Duplicate Steam webSession ignored');
        return;
    }
    webSessionProcessing = true;
    webSessionReceived = true;
    webCookies = Array.isArray(cookies) ? cookies : [];
    log('INFO', 'Steam web session received; cookies=' + webCookies.length);
    if (!webCookies.length) log('WARN', 'Steam web session returned no cookies');
    const headers = {'Cookie': cookieHeader()};

    const profile = await fetchUrl(`https://steamcommunity.com/profiles/${steamId}/`, headers);
    const account = await fetchUrl('https://store.steampowered.com/account/?l=english', headers);
    const transactions = await fetchUrl('https://store.steampowered.com/account/store_transactions/?l=english', {
        ...headers,
        'Referer':'https://store.steampowered.com/account/?l=english'
    });
    // Steam's Community Market page is a very reliable wallet-data source.
    const market = await fetchUrl('https://steamcommunity.com/market/?l=english', headers);
    const gcpd = await fetchUrl('https://steamcommunity.com/my/gcpd/730?l=english', headers);
    const levelData = extractLevelXp(gcpd.html);
    const badges = await fetchUrl(`https://steamcommunity.com/profiles/${steamId}/badges?l=english`, headers);
    const cardGames = badges.status===200 ? extractCardGames(badges.html) : [];
    log('INFO','Games with card drops remaining: '+cardGames.length);
    if (levelData.level !== null) log('INFO', 'CS2 level=' + levelData.level + ', xp=' + levelData.xp + ' / 5000');
    else log('WARN', 'CS2 level/XP not found on /my/gcpd/730 (HTTP ' + gcpd.status + ')');

    if (transactions.status === 200) log('INFO', 'store_transactions page loaded successfully');
    else log('WARN', 'store_transactions page did not return 200 (status=' + transactions.status + ')');

    const avatar = extractAvatar(profile.html);
    const profileWallet = extractWalletFromHtml(profile.html);
    const txWallet = extractWalletFromHtml(transactions.html);
    const accountWallet = extractWalletFromHtml(account.html);
    const marketWallet = extractWalletFromHtml(market.html);
    let gamesPageGames = [];
    let gamesPageCount = 0;

    if (profileWallet.formatted) log('INFO', 'Balance found on Steam profile: ' + profileWallet.formatted);
    else log('WARN', 'Balance was NOT found on Steam profile');
    if (txWallet.formatted) log('INFO', 'Balance found on store_transactions: ' + txWallet.formatted);
    else log('WARN', 'Balance was NOT found on store_transactions');
    if (accountWallet.formatted) log('INFO', 'Balance found on /account/: ' + accountWallet.formatted);
    else log('WARN', 'Balance was NOT found on /account/');
    if (marketWallet.formatted) log('INFO', 'Balance found on Steam Market: ' + marketWallet.formatted);
    else log('WARN', 'Balance was NOT found on Steam Market');
    if (avatar) log('INFO', 'Steam avatar found'); else log('WARN', 'Steam avatar was not found');

    // Only after profile/avatar/wallet data has been collected, scrape the exact
    // Steam Community Games -> All Games page requested by the user.
    try {
        const gamesResult = await scrapeCommunityGames(headers);
        gamesPageGames = Array.isArray(gamesResult?.games) ? gamesResult.games : [];
        gamesPageCount = Number.isInteger(gamesResult?.count) ? gamesResult.count : gamesPageGames.length;
    } catch (e) {
        log('WARN', 'Steam Community games scrape failed: ' + String(e.message || e));
        gamesPageGames = [];
    }

    const pageWallet = profileWallet.formatted ? profileWallet : (txWallet.formatted ? txWallet : (accountWallet.formatted ? accountWallet : marketWallet));
    const eventWallet = walletState && walletState.hasWallet ? formatWallet(walletState.balance, walletState.currency, true) : '';
    const finalBalance = pageWallet.formatted || eventWallet || '0';
    const finalCurrency = pageWallet.currency || (walletState ? walletState.currency : '') || 'USD';

    if (!finalBalance) {
        log('ERROR', 'Steam authorization succeeded, but wallet balance could not be read');
    } else {
        log('INFO', 'Final wallet balance: ' + finalBalance + ' (source=' + (pageWallet.formatted ? pageWallet.source : 'Steam wallet event') + ')');
    }

    finish({
        ok:true,
        steamid:steamId,
        avatar_url:avatar,
        balance:finalBalance,
        currency:finalCurrency,
        country:pageWallet.country || '',
        games:gamesPageGames,
        games_count:gamesPageCount || gamesPageGames.length,
        card_games:cardGames,
        level:levelData.level,
        xp:levelData.xp,
        balance_source:pageWallet.formatted ? pageWallet.source : (eventWallet ? 'steam-wallet-event' : ''),
        wallet_event:walletEventReceived,
        web_session:webSessionReceived,
        refresh_token:latestRefreshToken,
        web_cookies:webCookies
    });
});

client.on('error', (err) => finish({ok:false, auth_session_invalid:!!refreshToken && !client.steamID, error:'Steam client error: ' + String(err && (err.message || err))}));
client.on('disconnected', (eresult, msg) => finish({ok:false, auth_session_invalid:!!refreshToken && !client.steamID, error:'Steam disconnected: ' + String(msg || eresult)}));

if (!finished) {
    try {
        log('INFO', refreshToken ? 'Connecting to Steam using saved encrypted session' : 'Connecting to Steam using credentials');
        if (refreshToken) {
            client.logOn({refreshToken, steamID:steamId, machineName:`shark_${login}`});
        } else {
            const code = SteamTotp.getAuthCode(sharedSecret);
            log('INFO', 'Steam Guard TOTP generated successfully');
            client.logOn({accountName:login,password,twoFactorCode:code,machineName:`shark_${login}`});
        }
    } catch (e) { fail('logOn exception: ' + (e.message || e)); }
}
setTimeout(() => fail('Steam authorization timeout: no successful login/web session within 30 seconds'), 30000);
