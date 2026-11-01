// Exploração segura do site: só lê telas, nunca envia dados.
import { chromium } from 'playwright';
import dns from 'node:dns/promises';
import net from 'node:net';
import fs from 'node:fs';

const BASE = process.env.BASE_URL || '';
const ALLOWED = (process.env.ALLOWED_HOSTS || '').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean);
const OUT = process.env.OUT_DIR || 'evidencias';
const MAX_PAGES = 8, MAX_BUTTONS = 10;
// Botões com estas palavras nunca são clicados (podem alterar ou apagar dados).
const DANGER = /(excluir|apagar|deletar|remover|delete|remove|salvar|save|enviar|submit|send|confirmar|confirm|aprovar|rejeitar|pagar|comprar|assinar|cancelar|sair|logout|sign ?out|desconectar|publicar|resetar|reset|limpar|criar|cadastrar|gerar|rodar|executar|disparar)/i;

const report = { base_url: BASE, allowed_hosts: ALLOWED, started_at: new Date().toISOString(), screens: [], clicks: [], skipped: [], blocked_requests: [], errors: [] };
fs.mkdirSync(`${OUT}/capturas`, { recursive: true });
const save = () => fs.writeFileSync(`${OUT}/relatorio.json`, JSON.stringify(report, null, 2));

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const l = ip.toLowerCase();
  return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80') || l.startsWith('::ffff:') && isPrivateIp(l.slice(7));
}
const dnsCache = new Map();
async function hostIsSafe(host) {
  host = host.toLowerCase();
  if (!ALLOWED.includes(host)) return false;
  if (!dnsCache.has(host)) {
    dnsCache.set(host, (async () => {
      if (net.isIP(host)) return !isPrivateIp(host);
      const addrs = await dns.lookup(host, { all: true }).catch(() => []);
      return addrs.length > 0 && addrs.every((a) => !isPrivateIp(a.address));
    })());
  }
  return dnsCache.get(host);
}
async function urlIsSafe(u) {
  try { const x = new URL(u); return x.protocol === 'https:' && (await hostIsSafe(x.hostname)); } catch { return false; }
}

async function main() {
  if (!ALLOWED.length) throw new Error('Nenhum domínio autorizado informado.');
  if (!(await urlIsSafe(BASE))) throw new Error(`Endereço não autorizado ou interno: ${BASE}`);
  const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, serviceWorkers: 'block' });
  // Só leitura: qualquer pedido que não seja GET/HEAD é bloqueado; documentos fora da lista também.
  await context.route('**/*', async (route) => {
    const req = route.request();
    const u = req.url();
    if (u.startsWith('data:') || u.startsWith('blob:')) return route.continue();
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method())) { report.blocked_requests.push({ motivo: 'método ' + req.method(), url: u }); return route.abort('blockedbyclient'); }
    if (req.isNavigationRequest()) {
      if (!(await urlIsSafe(u))) { report.blocked_requests.push({ motivo: 'navegação fora dos domínios autorizados', url: u }); return route.abort('blockedbyclient'); }
      // Busca sem seguir redirecionamentos para conferir cada destino antes do navegador ir até ele.
      const res = await route.fetch({ maxRedirects: 0 }).catch(() => null);
      if (!res) return route.abort('failed');
      const loc = res.headers()['location'];
      if (res.status() >= 300 && res.status() < 400 && loc && !(await urlIsSafe(new URL(loc, u).href))) {
        report.blocked_requests.push({ motivo: 'redirecionamento para domínio não autorizado', url: new URL(loc, u).href.slice(0, 200) });
        return route.abort('blockedbyclient');
      }
      return route.fulfill({ response: res });
    }
    if (!req.isNavigationRequest() && /^http:/.test(u)) return route.abort('blockedbyclient');
    return route.continue();
  });
  const page = await context.newPage();
  page.on('pageerror', (e) => report.errors.push({ tipo: 'erro na página', detalhe: String(e).slice(0, 300) }));
  let shot = 0;
  const capture = async (label) => {
    const file = `capturas/${String(++shot).padStart(2, '0')}.png`;
    await page.screenshot({ path: `${OUT}/${file}` }).catch((e) => report.errors.push({ tipo: 'captura', label, detalhe: e.message }));
    return file;
  };
  const snap = async () => (await page.locator('body').ariaSnapshot({ timeout: 5000 }).catch(() => '')).slice(0, 6000);
  const open = async (u) => {
    const res = await page.goto(u, { waitUntil: 'networkidle', timeout: 30000 }).catch((e) => { report.errors.push({ tipo: 'abrir tela', url: u, detalhe: e.message.slice(0, 300) }); return null; });
    if (!(await urlIsSafe(page.url()))) { report.errors.push({ tipo: 'redirecionamento bloqueado', url: page.url() }); return false; }
    return res !== null;
  };

  const queue = [BASE]; const seen = new Set(); const md = [];
  while (queue.length && seen.size < MAX_PAGES) {
    const u = queue.shift(); if (seen.has(u)) continue; seen.add(u);
    if (!(await open(u))) continue;
    const path = new URL(page.url()).pathname;
    const aria = await snap();
    report.screens.push({ url: page.url(), captura: await capture(path), tamanho_mapa: aria.length });
    md.push(`## Tela ${path}\n${aria}`);
    const names = [];
    for (const b of (await page.getByRole('button').all()).slice(0, 30)) {
      const visible = await b.isVisible().catch(() => false);
      if (!visible) continue;
      const n = ((await b.innerText().catch(() => '')) || (await b.getAttribute('aria-label').catch(() => '')) || '').trim().replace(/\s+/g, ' ');
      const type = await b.getAttribute('type').catch(() => null);
      const inForm = await b.evaluate((el) => !!el.closest('form')).catch(() => false);
      if (!n) continue;
      if (DANGER.test(n) || type === 'submit' || inForm) { report.skipped.push({ tela: path, botao: n, motivo: DANGER.test(n) ? 'pode alterar dados' : 'envia formulário' }); continue; }
      names.push(n);
    }
    for (const n of [...new Set(names)].slice(0, MAX_BUTTONS)) {
      if (!(await open(u))) break;
      const ok = await page.getByRole('button', { name: n, exact: true }).first().click({ timeout: 3000 }).then(() => true).catch((e) => { report.errors.push({ tipo: 'clique', tela: path, botao: n, detalhe: e.message.slice(0, 200) }); return false; });
      if (!ok) continue;
      await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
      if (!(await urlIsSafe(page.url()))) { report.errors.push({ tipo: 'redirecionamento bloqueado', botao: n, url: page.url().slice(0, 200) }); continue; }
      const moved = page.url() !== u ? ` (foi para ${new URL(page.url()).pathname})` : '';
      report.clicks.push({ tela: path, botao: n, destino: page.url(), captura: await capture(`${path} ${n}`) });
      md.push(`### Em ${path}, depois de clicar no botão "${n}"${moved}\n${await snap()}`);
    }
    if (!(await open(u))) continue;
    const links = await page.$$eval('a[href]', (as) => as.map((a) => a.href)).catch(() => []);
    for (const l of links) { const c = l.split('#')[0]; if (!seen.has(c) && (await urlIsSafe(c))) queue.push(c); }
  }
  await browser.close();
  fs.writeFileSync('site-map.md', md.join('\n\n').slice(0, 80000));
  report.finished_at = new Date().toISOString();
  save();
  if (!report.screens.length) throw new Error('Nenhuma tela pôde ser aberta.');
  console.log(`Telas: ${report.screens.length} | cliques: ${report.clicks.length} | botões ignorados: ${report.skipped.length} | pedidos bloqueados: ${report.blocked_requests.length} | erros: ${report.errors.length}`);
}
main().catch((e) => { report.errors.push({ tipo: 'fatal', detalhe: e.message }); save(); console.error(e.message); process.exit(1); });
