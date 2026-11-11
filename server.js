'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const sharp = require('sharp');
const net = require('node:net');
const { promisify } = require('node:util');

// Carrega variáveis locais antes de importar módulos que leem configuração no require.
// Variáveis já definidas pelo ambiente/supervisor sempre têm precedência.
function loadLocalEnvFile(file = path.join(__dirname, '.env')) {
  if (!fs.existsSync(file)) return;
  const content = fs.readFileSync(file, 'utf8');
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const match = trimmed.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!match || Object.prototype.hasOwnProperty.call(process.env, match[1])) continue;
    let value = match[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    value = value.replace(/\\n/g, '\n').replace(/\\r/g, '\r');
    process.env[match[1]] = value;
  }
}
loadLocalEnvFile(path.join(__dirname, '.env.local'));
loadLocalEnvFile();

const { createDatabase, importLegacyExpenses, DATA_DIR } = require('./src/db');
const Finance = require('./src/finance');
const { createPdf, createXlsx, createAccountPdf, createAccountXlsx, createFinancialHistoryPdf, createFinancialHistoryXlsx } = require('./src/exports');
const Plans = require('./src/plans');
const MercadoPago = require('./src/mercadopago');
const { normalizeFullName, isValidFullName, isValidEmailAddress, isValidNewPassword } = require('./public/auth-validation');

const scryptAsync = promisify(crypto.scrypt);
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const HOST = (process.env.HOST || '127.0.0.1').trim() || '127.0.0.1';
const PORT = Number(process.env.PORT || 4173);
const NODE_ENV = process.env.NODE_ENV || 'development';
const SESSION_MS = 30 * 24 * 60 * 60 * 1000; // Sessão persistente por 30 dias
const ADMIN_SESSION_MS = 8 * 60 * 60 * 1000; // Sessão administrativa de 8 horas
const ACCESS_LOG_RETENTION_DAYS = Math.max(30, Math.min(730, Number(process.env.ACCESS_LOG_RETENTION_DAYS || 180)));
const DELETION_ARCHIVE_RETENTION_DAYS = Math.max(30, Math.min(365, Number(process.env.DELETION_ARCHIVE_RETENTION_DAYS || 180)));
const PREMIUM_TRIAL_DAYS = 7;
const PREMIUM_CYCLE_DAYS = 30;
const PREMIUM_PRICE_CENTS = Plans.PLANS.premium.priceCents;
const DEFAULT_THEME_SURFACES = Object.freeze({});
const THEME_SURFACE_KEYS = Object.freeze(['main', 'page', 'cards', 'menus', 'sidebar', 'modals', 'secondary']);
// Acesso Premium local: permite validar todos os recursos sem criar assinatura ou cobrança.
// Em produção, o acesso depende exclusivamente da integração de pagamentos ativada explicitamente.
const LOCAL_PREMIUM_ACCESS = NODE_ENV === 'development' && process.env.LOCAL_PREMIUM_ACCESS !== '0';
// Recurso de UX em desenvolvimento/teste apenas; nunca aceitar código arbitrário em produção.
const DEMO_SECOND_STEP = NODE_ENV !== 'production' && (NODE_ENV === 'test' ? process.env.OVBECK_DEMO_2FA === '1' : NODE_ENV === 'development' && ['127.0.0.1', 'localhost', '::1'].includes(HOST) && process.env.OVBECK_DEMO_2FA !== '0');
const PAYMENTS_ENABLED = NODE_ENV === 'production' && process.env.ENABLE_PAYMENTS === 'true';
const PREMIUM_TRIAL_ELIGIBILITY_RETENTION_DAYS = Math.max(365, Math.min(3650, Number(process.env.PREMIUM_TRIAL_ELIGIBILITY_RETENTION_DAYS || 1825)));
const REGISTRATION_ATTEMPT_THRESHOLD = Math.max(2, Math.min(1000, Number(process.env.REGISTRATION_ATTEMPT_THRESHOLD || (NODE_ENV === 'test' ? 1000 : 8))));
const REGISTRATION_ATTEMPT_WINDOW_MS = 60 * 60 * 1000;
const DEMO_PLAN_MS = PREMIUM_TRIAL_DAYS * 24 * 60 * 60 * 1000;
const LOGIN_SHORT_BLOCK_MS = Math.max(100, Number(process.env.LOGIN_SHORT_BLOCK_MS || 10_000));
const LOGIN_ACCOUNT_BLOCK_MS = Math.max(500, Number(process.env.LOGIN_ACCOUNT_BLOCK_MS || 60 * 60 * 1000));
const LOGIN_FAILS_BEFORE_SHORT_BLOCK = 5;
const LOGIN_FAILS_AFTER_SHORT_BLOCK = 2;
const MAX_BODY_BYTES = 64 * 1024;
const RATE_WINDOW_MS = 60_000;
const rateBuckets = new Map();
const DB = createDatabase();
const { ensureBootstrapAdmin } = require('./src/admin-bootstrap');

if (!Number.isInteger(PORT) || PORT < 0 || PORT > 65535) throw new Error('PORT precisa ser um inteiro entre 0 e 65535.');
if (HOST !== '127.0.0.1' && HOST !== 'localhost' && HOST !== '::1' && NODE_ENV !== 'production') {
  throw new Error('Por segurança, a execução de desenvolvimento deve usar HOST=127.0.0.1.');
}
fs.mkdirSync(DATA_DIR, { recursive: true });
const bootstrapAdminResult = ensureBootstrapAdmin(DB);
if (bootstrapAdminResult.status === 'created') process.stdout.write('[OVBECK] Conta administrativa local inicializada.\n');

const REGISTRATION_IP_LIMIT_ENABLED = NODE_ENV !== 'test' || process.env.ENFORCE_REGISTRATION_IP_LIMIT === '1';
function loadRegistrationIpHmacKey() {
  const configured = String(process.env.REGISTRATION_IP_HMAC_SECRET || '');
  if (configured) {
    if (Buffer.byteLength(configured) < 32) throw new Error('REGISTRATION_IP_HMAC_SECRET deve conter pelo menos 32 bytes.');
    return Buffer.from(configured, 'utf8');
  }
  if (NODE_ENV === 'production') throw new Error('Configure REGISTRATION_IP_HMAC_SECRET (mínimo de 32 bytes) antes de iniciar em produção.');
  const keyFile = path.join(DATA_DIR, '.registration-ip-hmac-secret');
  try {
    const existing = fs.readFileSync(keyFile);
    if (existing.length < 32) throw new Error('O segredo local de HMAC do IP está inválido; restaure um backup ou configure REGISTRATION_IP_HMAC_SECRET.');
    return existing;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    const generated = crypto.randomBytes(32);
    try { fs.writeFileSync(keyFile, generated, { flag: 'wx', mode: 0o600 }); return generated; }
    catch (writeError) {
      if (writeError.code !== 'EEXIST') throw writeError;
      const raced = fs.readFileSync(keyFile);
      if (raced.length < 32) throw new Error('O segredo local de HMAC do IP está inválido.');
      return raced;
    }
  }
}
const REGISTRATION_IP_HMAC_KEY = loadRegistrationIpHmacKey();

// Contas Premium já existentes não recebem um segundo teste gratuito na migração.
// Apenas o HMAC do e-mail é mantido na tabela de elegibilidade.

const CATEGORIES = Finance.CATEGORIES;
const CATEGORY_IDS = Finance.CATEGORY_IDS;
const PAYMENT_METHODS = Finance.PAYMENT_METHODS;
const RECURRENCES = Finance.RECURRENCES;
const STATUSES = Finance.STATUSES;
const REGISTRATION_COOLDOWN_ROUTES = new Set(['/api/auth/register-intent', '/api/auth/register-intent/update', '/api/auth/register/complete']);
const RATE_CONFIG = {
  // Login e o novo controle de cadastro possuem regras próprias.
  default: { limit: 180, window: RATE_WINDOW_MS },
  '/api/auth/login': { limit: 300, window: RATE_WINDOW_MS }
};
const STATIC_FILES = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/index.html', ['index.html', 'text/html; charset=utf-8']],
  ['/reset-password', ['index.html', 'text/html; charset=utf-8']],
  ['/reset-password/', ['index.html', 'text/html; charset=utf-8']],
  ['/styles.css', ['styles.css', 'text/css; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/icons.js', ['icons.js', 'text/javascript; charset=utf-8']],
  ['/finance.js', ['finance.js', 'text/javascript; charset=utf-8']],
  ['/auth-validation.js', ['auth-validation.js', 'text/javascript; charset=utf-8']],
  ['/favicon.svg', ['favicon.svg', 'image/svg+xml']],
  ['/assets/ovbeck/OVBECK_Favicon.png', ['assets/ovbeck/OVBECK_Favicon.png', 'image/png']],
  ['/assets/ovbeck/OVBECK_Logomarca_Horizontal_Claro.png', ['assets/ovbeck/OVBECK_Logomarca_Horizontal_Claro.png', 'image/png']],
  ['/assets/ovbeck/OVBECK_Logomarca_Horizontal_Escuro.png', ['assets/ovbeck/OVBECK_Logomarca_Horizontal_Escuro.png', 'image/png']],
  ['/assets/ovbeck/OVBECK_Simbolo.png', ['assets/ovbeck/OVBECK_Simbolo.png', 'image/png']],
  ['/assets/ovbeck/OVBECK_Compatibilidade_Dispositivos.svg', ['assets/ovbeck/OVBECK_Compatibilidade_Dispositivos.svg', 'image/svg+xml']],
  ['/assets/ovbeck/OVBECK_Simbolo.svg', ['assets/ovbeck/OVBECK_Simbolo.svg', 'image/svg+xml']],
  ['/assets/ovbeck/OVBECK_Logomarca_Claro.svg', ['assets/ovbeck/OVBECK_Logomarca_Claro.svg', 'image/svg+xml']],
  ['/assets/ovbeck/OVBECK_Logomarca_Escuro.svg', ['assets/ovbeck/OVBECK_Logomarca_Escuro.svg', 'image/svg+xml']],
  ['/assets/ovbeck/OVBECK_Logomarca_Monocromatica_Clara.png', ['assets/ovbeck/OVBECK_Logomarca_Monocromatica_Clara.png', 'image/png']],
  ['/assets/ovbeck/OVBECK_Logomarca_Monocromatica_Escura.png', ['assets/ovbeck/OVBECK_Logomarca_Monocromatica_Escura.png', 'image/png']],
  ['/admin', ['admin.html', 'text/html; charset=utf-8']],
  ['/admin/', ['admin.html', 'text/html; charset=utf-8']],
  ['/admin.css', ['admin.css', 'text/css; charset=utf-8']],
  ['/admin.js', ['admin.js', 'text/javascript; charset=utf-8']]
]);

function nowISO() { return new Date().toISOString(); }
function todayLocal() {
  const parts = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Sao_Paulo', year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(new Date());
  const get = (type) => parts.find((part) => part.type === type).value;
  return `${get('year')}-${get('month')}-${get('day')}`;
}
function currentMonth() { return todayLocal().slice(0, 7); }
function daysUntilExpiry(expiry, today = todayLocal()) {
  if (typeof expiry !== 'string' || !/^\d{4}-\d{2}-\d{2}T/.test(expiry)) return null;
  const expiryDay = expiry.slice(0, 10);
  if (!Finance.isISODate(expiryDay) || !Finance.isISODate(today)) return null;
  const day = (value) => Date.parse(`${value}T00:00:00Z`);
  return Math.ceil((day(expiryDay) - day(today)) / 86400000);
}
function demoPlanPeriod(now = new Date()) {
  return { startedAt: now.toISOString(), expiresAt: new Date(now.getTime() + DEMO_PLAN_MS).toISOString() };
}
function premiumTrialPeriod(now = new Date()) {
  const startedAt = now.toISOString();
  const endsAt = new Date(now.getTime() + PREMIUM_TRIAL_DAYS * 86400000).toISOString();
  const firstBillingAt = endsAt;
  const firstBillingPeriodEndsAt = new Date(Date.parse(firstBillingAt) + PREMIUM_CYCLE_DAYS * 86400000).toISOString();
  return { startedAt, endsAt, firstBillingAt, firstBillingPeriodEndsAt };
}

// Checkout só é disponibilizado quando token, origem pública e segredo de webhook estão configurados.
// Sem webhook autenticado não há ativação de benefícios: o retorno do navegador nunca confirma pagamento.
function paymentConfiguration() {
  const provider = MercadoPago.configuration();
  const missing = [...(provider.missing || [])];
  let publicOrigin = false;
  try {
    const origin = new URL(String(process.env.APP_ORIGIN || ''));
    publicOrigin = Boolean(origin.protocol === 'https:' && origin.hostname && !['localhost','127.0.0.1','::1'].includes(origin.hostname));
  } catch { publicOrigin = false; }
  if (!publicOrigin && !missing.includes('APP_ORIGIN_PUBLIC_HTTPS')) missing.push('APP_ORIGIN_PUBLIC_HTTPS');
  const checkoutConfigured = Boolean(provider.checkoutConfigured && publicOrigin);
  const webhookConfigured = Boolean(provider.webhookConfigured);
  return { configured: checkoutConfigured && webhookConfigured, checkoutConfigured, webhookConfigured, missing };
}
function paymentCheckoutAvailable() { return PAYMENTS_ENABLED && paymentConfiguration().configured; }
function saveAppSetting(key, value) {
  DB.prepare(`INSERT INTO app_settings(setting_key, setting_value, updated_at) VALUES (?, ?, ?)
    ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value, updated_at=excluded.updated_at`)
    .run(key, String(value), nowISO());
}
async function getOrCreateMercadoPagoPlan(trial) {
  const key = trial ? 'mercadopago_plan_premium_trial7_v1' : 'mercadopago_plan_premium_cycle30_v1';
  const cached = DB.prepare('SELECT setting_value FROM app_settings WHERE setting_key = ?').get(key)?.setting_value;
  if (cached) {
    try {
      const existing = await MercadoPago.getPlan(cached);
      if (existing?.id && existing.status !== 'cancelled' && existing.status !== 'canceled') return String(existing.id);
    } catch { /* Plano removido ou indisponível: recriar de forma idempotente. */ }
  }
  const plan = await MercadoPago.createPremiumPlan({ trial, backUrl: `${String(process.env.APP_ORIGIN || '').replace(/\/$/, '')}/?billing=return` });
  if (!plan?.id) throw new Error('O provedor não retornou um identificador válido para o plano de assinatura.');
  saveAppSetting(key, plan.id);
  return String(plan.id);
}
async function createPremiumCheckoutForUser(user, { trialConsent = false } = {}) {
  const cfg = paymentConfiguration();
  if (!cfg.configured) {
    const error = new Error('A contratação Premium não está disponível neste momento. Tente novamente mais tarde.');
    error.code = 'PREMIUM_CHECKOUT_UNAVAILABLE'; error.status = 503; error.missing = cfg.missing;
    throw error;
  }
  const existing = DB.prepare(`SELECT * FROM payment_subscriptions WHERE user_id = ? AND status IN ('creating','pending','authorized','trialing','active','past_due') ORDER BY created_at DESC LIMIT 1`).get(user.id);
  if (existing?.checkout_url && ['creating','pending'].includes(existing.status)) {
    return { checkoutUrl: existing.checkout_url, trialDays: existing.trial_days, subscriptionId: existing.provider_subscription_id, reused: true };
  }
  if (existing) {
    const error = new Error(existing.status === 'past_due' ? 'Existe uma assinatura com pagamento pendente ou atrasado. Regularize o estado atual antes de iniciar outra contratação.' : 'Já existe uma assinatura Premium associada a esta conta.');
    error.code = 'PREMIUM_SUBSCRIPTION_EXISTS'; error.status = 409;
    throw error;
  }
  const stamp = nowISO();
  const emailHash = premiumTrialEmailHash(user.email);
  const previousTrial = DB.prepare('SELECT expires_at FROM premium_trial_eligibility WHERE email_hash = ?').get(emailHash);
  const trial = Boolean(trialConsent && (!previousTrial || previousTrial.expires_at <= stamp));
  // A elegibilidade anterior não impede uma contratação paga; apenas remove o teste gratuito.
  const planId = await getOrCreateMercadoPagoPlan(trial);
  const localId = crypto.randomUUID();
  const externalReference = `OVBECK-${user.id}-${crypto.randomUUID()}`;
  DB.prepare(`INSERT INTO payment_subscriptions(id, user_id, provider_plan_id, external_reference, status, trial_days, amount_cents, currency, created_at, updated_at)
    VALUES (?, ?, ?, ?, 'creating', ?, ?, 'BRL', ?, ?)`)
    .run(localId, user.id, planId, externalReference, trial ? 7 : 0, PREMIUM_PRICE_CENTS, stamp, stamp);
  try {
    const subscription = await MercadoPago.createSubscription({
      planId, payerEmail: user.email, externalReference,
      backUrl: `${String(process.env.APP_ORIGIN || '').replace(/\/$/, '')}/?billing=return`,
      notificationUrl: `${String(process.env.APP_ORIGIN || '').replace(/\/$/, '')}/api/webhooks/mercadopago`,
      idempotencyKey: `ovbeck-sub-${localId}`
    });
    const updated = nowISO();
    DB.exec('BEGIN IMMEDIATE');
    try {
      DB.prepare(`UPDATE payment_subscriptions SET provider_subscription_id=?, status='pending', checkout_url=?, provider_status=?, next_payment_at=?, updated_at=? WHERE id=?`)
        .run(subscription.id, subscription.initPoint, subscription.status, subscription.nextPaymentDate, updated, localId);
      DB.prepare(`UPDATE users SET premium_subscription_status='pending', premium_provider_subscription_id=?, premium_next_payment_at=?, premium_trial_consent_at=CASE WHEN ? THEN ? ELSE premium_trial_consent_at END, updated_at=? WHERE id=?`)
        .run(subscription.id, subscription.nextPaymentDate, trial ? 1 : 0, trial ? updated : null, updated, user.id);
      DB.exec('COMMIT');
    } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
    return { checkoutUrl: subscription.initPoint, trialDays: trial ? 7 : 0, subscriptionId: subscription.id, reused: false };
  } catch (error) {
    DB.prepare(`UPDATE payment_subscriptions SET status='rejected', provider_status=?, updated_at=? WHERE id=?`)
      .run(String(error.providerCode || error.message).slice(0, 180), nowISO(), localId);
    throw error;
  }
}

function plusDaysIso(value, days) {
  const base = Date.parse(value || nowISO());
  return new Date(base + days * 86400000).toISOString();
}
function providerPaymentStatus(payment) {
  const status = String(payment?.status || '').toLowerCase();
  if (status === 'approved') return 'paid';
  if (status === 'refunded' || status === 'partially_refunded') return 'refunded';
  if (status === 'charged_back') return 'charged_back';
  if (status === 'cancelled' || status === 'canceled') return 'canceled';
  if (status === 'rejected') return 'rejected';
  if (['pending', 'in_process', 'authorized'].includes(status)) return 'pending';
  return null;
}
function providerSubscriptionStatus(value) {
  const status = String(value || '').toLowerCase();
  if (status === 'authorized') return 'authorized';
  if (status === 'pending') return 'pending';
  if (status === 'paused') return 'paused';
  if (status === 'cancelled' || status === 'canceled') return 'canceled';
  if (status === 'rejected') return 'rejected';
  if (status === 'expired') return 'expired';
  return 'pending';
}
function applyProviderSubscription(providerSubscription, receivedAt = nowISO()) {
  const providerId = String(providerSubscription?.id || '');
  const externalReference = String(providerSubscription?.external_reference || '');
  if (!providerId && !externalReference) return { ignored: true, reason: 'subscription_reference_missing' };
  const local = DB.prepare(`SELECT * FROM payment_subscriptions WHERE provider_subscription_id = ? OR external_reference = ? LIMIT 1`)
    .get(providerId || '__none__', externalReference || '__none__');
  if (!local) return { ignored: true, reason: 'subscription_not_found' };
  if (String(providerSubscription.preapproval_plan_id || '') !== String(local.provider_plan_id || '')) {
    return { ignored: true, reason: 'provider_plan_mismatch' };
  }
  const recurring = providerSubscription.auto_recurring || {};
  if (recurring.transaction_amount != null && (Math.round(Number(recurring.transaction_amount) * 100) !== PREMIUM_PRICE_CENTS || String(recurring.currency_id || '') !== 'BRL' || Number(recurring.frequency) !== PREMIUM_CYCLE_DAYS || String(recurring.frequency_type || '') !== 'days')) {
    return { ignored: true, reason: 'provider_recurrence_mismatch' };
  }
  const eventModified = providerSubscription.last_modified || providerSubscription.date_created || receivedAt;
  if (local.last_provider_event_at && Date.parse(eventModified) <= Date.parse(local.last_provider_event_at)) {
    return { ignored: true, reason: 'stale_provider_event' };
  }
  const normalized = providerSubscriptionStatus(providerSubscription.status);
  const nextPaymentAt = providerSubscription.next_payment_date || null;
  const authorized = normalized === 'authorized';
  const paidForThisSubscription = Boolean(DB.prepare("SELECT 1 FROM payment_records WHERE payment_subscription_id=? AND status='paid' LIMIT 1").get(local.id));
  const trialActive = authorized && Number(local.trial_days) === PREMIUM_TRIAL_DAYS
    && nextPaymentAt && Date.parse(nextPaymentAt) > Date.now();
  // Uma assinatura apenas autorizada sem teste vigente ou pagamento aprovado não concede Premium.
  const localStatus = trialActive ? 'trialing'
    : normalized === 'authorized' ? (paidForThisSubscription ? 'active' : 'pending')
      : normalized;
  const stamp = nowISO();
  const trialStartedAt = trialActive ? (local.trial_started_at || providerSubscription.date_created || local.created_at || stamp) : null;
  const trialEndsAt = trialActive ? nextPaymentAt : null;
  const firstBillingAt = Number(local.trial_days) === PREMIUM_TRIAL_DAYS ? (local.trial_ends_at || nextPaymentAt || null) : nextPaymentAt;
  const userPlan = ['trialing', 'active'].includes(localStatus) ? 'premium' : 'base';
  const planStatus = localStatus === 'canceled' || localStatus === 'expired' || localStatus === 'rejected' ? 'expired' : userPlan === 'premium' ? 'legacy' : 'free';
  DB.exec('BEGIN IMMEDIATE');
  try {
    DB.prepare(`UPDATE payment_subscriptions SET provider_subscription_id=COALESCE(provider_subscription_id,?), status=?, provider_status=?,
      authorized_at=CASE WHEN ? THEN COALESCE(authorized_at,?) ELSE authorized_at END,
      trial_started_at=CASE WHEN ?='trialing' THEN COALESCE(trial_started_at,?) ELSE trial_started_at END,
      trial_ends_at=CASE WHEN ?='trialing' THEN COALESCE(trial_ends_at,?) ELSE trial_ends_at END,
      next_payment_at=?, period_started_at=CASE WHEN ?='active' THEN COALESCE(period_started_at,?) ELSE period_started_at END,
      period_ends_at=CASE WHEN ?='active' THEN ? ELSE period_ends_at END,
      canceled_at=CASE WHEN ?='canceled' THEN COALESCE(canceled_at,?) ELSE canceled_at END,
      last_provider_event_at=?, updated_at=? WHERE id=?`)
      .run(providerId || null, localStatus, String(providerSubscription.status || '').slice(0, 80), authorized ? 1 : 0,
        providerSubscription.date_created || stamp, localStatus, trialStartedAt, localStatus, trialEndsAt, nextPaymentAt,
        localStatus, stamp, localStatus, nextPaymentAt ? plusDaysIso(nextPaymentAt, PREMIUM_CYCLE_DAYS) : plusDaysIso(stamp, PREMIUM_CYCLE_DAYS),
        localStatus, stamp, eventModified, stamp, local.id);
    if (trialActive) grantPremiumTrialEligibility(DB.prepare('SELECT email FROM users WHERE id=?').get(local.user_id)?.email, stamp);
    DB.prepare(`UPDATE users SET plan=?, plan_status=?, plan_started_at=CASE WHEN ?='base' THEN NULL ELSE COALESCE(plan_started_at,?) END,
      plan_expires_at=CASE WHEN ?='base' THEN NULL ELSE ? END,
      premium_trial_started_at=CASE WHEN ?='trialing' THEN COALESCE(premium_trial_started_at,?) ELSE premium_trial_started_at END,
      premium_trial_ends_at=CASE WHEN ?='trialing' THEN COALESCE(premium_trial_ends_at,?) ELSE premium_trial_ends_at END,
      premium_first_billing_at=COALESCE(?,premium_first_billing_at), premium_first_billing_period_ends_at=CASE WHEN ?='active' THEN ? ELSE premium_first_billing_period_ends_at END,
      premium_subscription_status=?, premium_provider_subscription_id=?, premium_next_payment_at=?, updated_at=?
      WHERE id=? AND account_status='active'`)
      .run(userPlan, planStatus, userPlan, trialStartedAt || stamp, userPlan, trialEndsAt || (localStatus === 'active' ? null : null),
        localStatus, trialStartedAt || stamp, localStatus, trialEndsAt, firstBillingAt, localStatus,
        nextPaymentAt ? plusDaysIso(nextPaymentAt, PREMIUM_CYCLE_DAYS) : null,
        localStatus, providerId || local.provider_subscription_id, nextPaymentAt, stamp, local.user_id);
    DB.exec('COMMIT');
  } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
  return { updated: true, userId: local.user_id, status: localStatus };
}
async function applyAuthorizedPayment(providerInvoice, receivedAt = nowISO()) {
  const subscriptionId = String(providerInvoice?.preapproval_id || '');
  if (!subscriptionId) return { ignored: true, reason: 'invoice_subscription_missing' };
  const local = DB.prepare('SELECT * FROM payment_subscriptions WHERE provider_subscription_id=?').get(subscriptionId);
  if (!local) return { ignored: true, reason: 'subscription_not_found' };
  const paymentId = providerInvoice?.payment?.id ? String(providerInvoice.payment.id) : null;
  const payment = paymentId ? await MercadoPago.getPayment(paymentId) : null;
  if (!payment) return { ignored: true, reason: 'invoice_without_final_payment' };
  const mapped = providerPaymentStatus(payment);
  if (!mapped) return { ignored: true, reason: 'unknown_payment_status' };
  const amount = Number(payment.transaction_amount);
  const amountCents = Number.isFinite(amount) ? Math.round(amount * 100) : null;
  if (amountCents !== PREMIUM_PRICE_CENTS || String(payment.currency_id || '') !== 'BRL') {
    return { ignored: true, reason: 'payment_amount_or_currency_mismatch' };
  }
  const paymentSubscriptionId = String(payment.preapproval_id || payment.metadata?.preapproval_id || subscriptionId);
  if (paymentSubscriptionId !== subscriptionId) return { ignored: true, reason: 'payment_subscription_mismatch' };
  const stamp = nowISO();
  const paidAt = mapped === 'paid' ? (payment.date_approved || payment.date_last_updated || stamp) : null;
  const dueAt = providerInvoice.debit_date || local.next_payment_at || payment.date_of_expiration || null;
  DB.exec('BEGIN IMMEDIATE');
  try {
    DB.prepare(`INSERT INTO payment_records(id,user_id,provider,provider_payment_id,plan,amount_cents,currency,due_at,paid_at,status,provider_status,created_at,updated_at,payment_subscription_id)
      VALUES (?,?,?,?, 'premium', ?, 'BRL', ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(provider,provider_payment_id) DO UPDATE SET due_at=excluded.due_at,paid_at=COALESCE(excluded.paid_at,payment_records.paid_at),
      status=excluded.status,provider_status=excluded.provider_status,updated_at=excluded.updated_at,
      payment_subscription_id=COALESCE(payment_records.payment_subscription_id,excluded.payment_subscription_id)`)
      .run(crypto.randomUUID(), local.user_id, 'mercadopago', String(payment.id), amountCents, dueAt, paidAt, mapped,
        String(payment.status_detail || payment.status || '').slice(0, 80), stamp, stamp, local.id);
    const stillInTrial = local.status === 'trialing' && local.trial_ends_at && Date.parse(local.trial_ends_at) > Date.now();
    const nextStatus = mapped === 'paid' ? 'active'
      : mapped === 'pending' ? (stillInTrial ? 'trialing' : 'past_due')
        : ['refunded','charged_back','rejected','canceled'].includes(mapped) ? 'canceled' : 'past_due';
    const nextPlan = ['paid'].includes(mapped) || (mapped === 'pending' && stillInTrial) ? 'premium' : 'base';
    DB.prepare(`UPDATE payment_subscriptions SET status=?, provider_status=?, next_payment_at=?, period_started_at=CASE WHEN ?='paid' THEN ? ELSE period_started_at END,
      period_ends_at=CASE WHEN ?='paid' THEN ? ELSE period_ends_at END, last_provider_event_at=?, updated_at=? WHERE id=?`)
      .run(nextStatus, String(payment.status_detail || payment.status || '').slice(0, 80), local.next_payment_at,
        mapped, paidAt, mapped, local.next_payment_at ? plusDaysIso(local.next_payment_at, PREMIUM_CYCLE_DAYS) : plusDaysIso(paidAt || stamp, PREMIUM_CYCLE_DAYS),
        payment.date_last_updated || receivedAt, stamp, local.id);
    DB.prepare(`UPDATE users SET plan=?, plan_status=?, premium_subscription_status=?, premium_next_payment_at=?,
      plan_started_at=CASE WHEN ?='paid' THEN COALESCE(plan_started_at,?) ELSE NULL END,
      plan_expires_at=CASE WHEN ?='paid' THEN ? ELSE NULL END, updated_at=? WHERE id=? AND account_status='active'`)
      .run(nextPlan, nextStatus === 'trialing' ? 'trial' : mapped === 'paid' ? 'paid' : 'free', nextStatus, local.next_payment_at,
        mapped, paidAt, mapped, local.next_payment_at ? plusDaysIso(local.next_payment_at, PREMIUM_CYCLE_DAYS) : null,
        stamp, local.user_id);
    DB.exec('COMMIT');
  } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
  return { updated: true, userId: local.user_id, paymentStatus: mapped };
}
async function handleMercadoPagoWebhook(req, res, url) {
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); sendError(res, 405, 'Método não permitido.'); return; }
  const config = paymentConfiguration();
  if (!config.webhookConfigured) { sendError(res, 503, 'Webhook de pagamento ainda não configurado.'); return; }
  let body;
  try { body = await readJson(req); } catch { sendError(res, 400, 'Notificação inválida.'); return; }
  const resourceId = String(body?.data?.id || url.searchParams.get('data.id') || body?.id || '').trim();
  const eventType = String(body?.type || body?.topic || url.searchParams.get('type') || url.searchParams.get('topic') || '').trim();
  const action = String(body?.action || '').trim();
  const requestId = String(req.headers['x-request-id'] || '').trim();
  const signature = String(req.headers['x-signature'] || '').trim();
  if (!resourceId || !eventType || !MercadoPago.verifyWebhookSignature({ signature, requestId, dataId: resourceId })) {
    sendError(res, 401, 'Assinatura de notificação inválida.'); return;
  }
  const eventKey = `${eventType}:${resourceId}:${action}`.slice(0, 240);
  const stamp = nowISO();
  DB.exec('BEGIN IMMEDIATE');
  let claimed = false;
  try {
    DB.prepare(`INSERT OR IGNORE INTO payment_webhook_events(id,event_key,event_type,resource_id,status,received_at)
      VALUES (?,?,?,?,'received',?)`).run(crypto.randomUUID(), eventKey, eventType.slice(0, 100), resourceId.slice(0, 180), stamp);
    const staleProcessingBefore = new Date(Date.now() - 5 * 60_000).toISOString();
    const claim = DB.prepare(`UPDATE payment_webhook_events SET status='processing', error_code=NULL, received_at=? WHERE event_key=? AND (status IN ('received','failed') OR (status='processing' AND received_at <= ?))`).run(stamp, eventKey, staleProcessingBefore);
    claimed = Number(claim.changes || 0) === 1;
    DB.exec('COMMIT');
  } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
  if (!claimed) { sendJson(res, 200, { received: true, duplicate: true }); return; }
  try {
    let outcome = { ignored: true, reason: 'unsupported_event' };
    if (eventType === 'subscription_preapproval') {
      const subscription = await MercadoPago.getSubscription(resourceId);
      outcome = applyProviderSubscription(subscription, stamp);
    } else if (eventType === 'subscription_authorized_payment') {
      const invoice = await MercadoPago.getAuthorizedPayment(resourceId);
      outcome = await applyAuthorizedPayment(invoice, stamp);
    } else if (eventType === 'payment') {
      const payment = await MercadoPago.getPayment(resourceId);
      const preapprovalId = String(payment?.metadata?.preapproval_id || payment?.preapproval_id || '').trim();
      const externalReference = String(payment?.external_reference || '');
      const local = preapprovalId ? DB.prepare('SELECT * FROM payment_subscriptions WHERE provider_subscription_id=?').get(preapprovalId)
        : externalReference ? DB.prepare('SELECT * FROM payment_subscriptions WHERE external_reference=?').get(externalReference) : null;
      if (local) {
        outcome = await applyAuthorizedPayment({ preapproval_id: preapprovalId, debit_date: payment.date_of_expiration, payment: { id: payment.id } }, stamp);
      }
    }
    DB.prepare(`UPDATE payment_webhook_events SET status=?, processed_at=?, error_code=? WHERE event_key=?`)
      .run(outcome.ignored ? 'ignored' : 'processed', nowISO(), outcome.reason || null, eventKey);
    sendJson(res, 200, { received: true, processed: !outcome.ignored, reason: outcome.reason || null });
  } catch (error) {
    DB.prepare(`UPDATE payment_webhook_events SET status='failed', processed_at=?, error_code=? WHERE event_key=?`)
      .run(nowISO(), String(error.providerCode || error.message).slice(0, 80), eventKey);
    sendError(res, 500, 'Não foi possível processar a notificação. O provedor poderá reenviá-la.');
  }
}

function loginAttemptBucketKey(userId, req) {
  const ipHash = registrationIpHashFromAddress(requestIp(req)) || 'unknown';
  return crypto.createHmac('sha256', REGISTRATION_IP_HMAC_KEY).update(`client-login-v1:${userId}:${ipHash}`).digest('hex');
}
function loginLockState(user) {
  const until = user?.login_locked_until ? Date.parse(user.login_locked_until) : NaN;
  if (!Number.isFinite(until) || until <= Date.now()) return { locked: false, remainingSeconds: 0 };
  return { locked: true, remainingSeconds: Math.max(1, Math.ceil((until - Date.now()) / 1000)), until: user.login_locked_until };
}
function activeShortLoginBlock(userId, req) {
  const key = loginAttemptBucketKey(userId, req);
  const row = DB.prepare('SELECT short_blocked_until, stage, failed_attempts FROM client_login_attempt_buckets WHERE bucket_key = ?').get(key);
  const until = row?.short_blocked_until ? Date.parse(row.short_blocked_until) : NaN;
  if (Number.isFinite(until) && until > Date.now()) return { blocked: true, remainingSeconds: Math.max(1, Math.ceil((until - Date.now()) / 1000)), warning: Number(row.stage) >= 1 };
  return { blocked: false, warning: Number(row?.stage) >= 1 && Number(row?.failed_attempts) <= 1 };
}
function recordClientLoginFailure(userId, req) {
  const stamp = nowISO(); const stampMs = Date.parse(stamp); const key = loginAttemptBucketKey(userId, req);
  DB.exec('BEGIN IMMEDIATE');
  try {
    const user = DB.prepare('SELECT id, login_locked_until FROM users WHERE id=?').get(userId);
    if (!user) { DB.exec('ROLLBACK'); return { locked: false }; }
    const lock = loginLockState(user);
    if (lock.locked) { DB.exec('ROLLBACK'); return { locked: true, remainingSeconds: lock.remainingSeconds, until: lock.until }; }
    if (user.login_locked_until) DB.prepare('UPDATE users SET login_locked_until=NULL, login_lock_started_at=NULL WHERE id=?').run(userId);
    const current = DB.prepare('SELECT * FROM client_login_attempt_buckets WHERE bucket_key=?').get(key);
    let stage = Number(current?.stage || 0); let failures = Number(current?.failed_attempts || 0);
    const shortUntil = current?.short_blocked_until ? Date.parse(current.short_blocked_until) : 0;
    if (shortUntil > stampMs) {
      DB.exec('COMMIT');
      return { shortBlocked: true, remainingSeconds: Math.max(1, Math.ceil((shortUntil - stampMs) / 1000)), stage };
    }
    if (shortUntil && shortUntil <= stampMs && stage === 0) { stage = 1; failures = 0; }
    failures += 1;
    let nextShort = null; let accountUntil = null; let warning = false;
    if (stage === 0 && failures >= LOGIN_FAILS_BEFORE_SHORT_BLOCK) {
      stage = 1; failures = 0; nextShort = new Date(stampMs + LOGIN_SHORT_BLOCK_MS).toISOString();
    } else if (stage >= 1 && failures >= LOGIN_FAILS_AFTER_SHORT_BLOCK) {
      stage = 2; failures = 0; accountUntil = new Date(stampMs + LOGIN_ACCOUNT_BLOCK_MS).toISOString();
      DB.prepare('UPDATE users SET login_locked_until=?, login_lock_started_at=?, updated_at=? WHERE id=?')
        .run(accountUntil, stamp, stamp, userId);
      DB.prepare('DELETE FROM sessions WHERE user_id=?').run(userId);
      DB.prepare(`INSERT INTO user_security_events(id,user_id,event_type,source_ip_hash,details_json,created_at,source_ip_address)
        VALUES (?,?, 'client_login_account_locked', ?, ?, ?, ?)`)
        .run(crypto.randomUUID(), userId, registrationIpHashFromAddress(requestIp(req)), JSON.stringify({ lockedUntil: accountUntil, durationSeconds: Math.round(LOGIN_ACCOUNT_BLOCK_MS / 1000) }), stamp, normalizeIpAddress(requestIp(req)));
    } else if (stage >= 1) warning = true;
    DB.prepare(`INSERT INTO client_login_attempt_buckets(bucket_key,user_id,failed_attempts,stage,short_blocked_until,last_failed_at,updated_at)
      VALUES (?,?,?,?,?,?,?) ON CONFLICT(bucket_key) DO UPDATE SET failed_attempts=excluded.failed_attempts,stage=excluded.stage,
      short_blocked_until=excluded.short_blocked_until,last_failed_at=excluded.last_failed_at,updated_at=excluded.updated_at`)
      .run(key, userId, failures, stage, nextShort, stamp, stamp);
    if (nextShort) {
      DB.prepare(`INSERT INTO user_security_events(id,user_id,event_type,source_ip_hash,details_json,created_at,source_ip_address)
        VALUES (?,?, 'client_login_short_locked', ?, ?, ?, ?)`)
        .run(crypto.randomUUID(), userId, registrationIpHashFromAddress(requestIp(req)), JSON.stringify({ lockedUntil: nextShort, durationSeconds: Math.round(LOGIN_SHORT_BLOCK_MS / 1000) }), stamp, normalizeIpAddress(requestIp(req)));
    }
    DB.exec('COMMIT');
    if (accountUntil) return { locked: true, remainingSeconds: Math.max(1, Math.ceil((Date.parse(accountUntil) - Date.now()) / 1000)), until: accountUntil };
    if (nextShort) return { shortBlocked: true, remainingSeconds: Math.max(1, Math.ceil((Date.parse(nextShort) - Date.now()) / 1000)), stage };
    return { warning, attemptsAfterCooldown: stage >= 1 ? failures : 0 };
  } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
}
function clearClientLoginFailures(userId) {
  DB.prepare('DELETE FROM client_login_attempt_buckets WHERE user_id=?').run(userId);
  DB.prepare('UPDATE users SET login_locked_until=NULL, login_lock_started_at=NULL WHERE id=?').run(userId);
}
function resetExpiredLoginLock(user) {
  const until = user?.login_locked_until ? Date.parse(user.login_locked_until) : NaN;
  if (Number.isFinite(until) && until <= Date.now()) {
    DB.prepare('UPDATE users SET login_locked_until=NULL, login_lock_started_at=NULL WHERE id=?').run(user.id);
    DB.prepare('DELETE FROM client_login_attempt_buckets WHERE user_id=?').run(user.id);
    return true;
  }
  return false;
}
function adminLoginLockedUntil(user) {
  const until = user?.login_locked_until ? Date.parse(user.login_locked_until) : NaN;
  return Number.isFinite(until) && until > Date.now() ? user.login_locked_until : null;
}
function minimumExpenseDate() { return '1950-01-01'; }
function isAllowedExpenseDate(value, optional = false) {
  if (optional && (value === undefined || value === null || value === '')) return true;
  return Finance.isISODate(value) && value >= minimumExpenseDate();
}
function normalizeEmail(value) { return String(value || '').trim().toLowerCase(); }
function isPlainObject(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function hasOnlyKeys(value, keys) { return Object.keys(value).every((key) => keys.includes(key)); }
function validateText(value, max, required = false) { return typeof value === 'string' && value.length <= max && (!required || value.trim().length > 0); }
function parseCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const pair of raw.split(';')) {
    const index = pair.indexOf('=');
    if (index < 0) continue;
    if (pair.slice(0, index).trim() === name) { try { return decodeURIComponent(pair.slice(index + 1).trim()); } catch { return null; } }
  }
  return null;
}
function hashToken(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function timingSafeString(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function isSecureRequest(req) { return Boolean(req.socket.encrypted); }
function expectedOrigin(req) {
  if (process.env.APP_ORIGIN) {
    try { return new URL(process.env.APP_ORIGIN).origin; } catch { return null; }
  }
  const protocol = isSecureRequest(req) ? 'https:' : 'http:';
  return `${protocol}//${req.headers.host || ''}`;
}
function originIsAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).origin === expectedOrigin(req); } catch { return false; }
}
function secureCookie(token, maxAge, name = 'ct_session') {
  const parts = [`${name}=${encodeURIComponent(token)}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${maxAge}`];
  if (NODE_ENV === 'production') parts.push('Secure');
  return parts.join('; ');
}
function clearCookie(name = 'ct_session') { return `${name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${NODE_ENV === 'production' ? '; Secure' : ''}`; }

function sendJson(res, status, body, headers = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(payload),
    ...headers
  });
  res.end(payload);
}
function sendError(res, status, message, extra = {}) { sendJson(res, status, { error: message, ...extra }); }

function readJson(req, maxBytes = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const type = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (type !== 'application/json') {
      const error = new Error('Envie os dados como application/json.'); error.statusCode = 415; reject(error); req.resume(); return;
    }
    let size = 0;
    const chunks = [];
    let done = false;
    const finish = (error, value) => { if (done) return; done = true; error ? reject(error) : resolve(value); };
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        const error = new Error(`A requisição ultrapassou o limite de ${Math.round(maxBytes / 1024)} KB.`); error.statusCode = 413;
        finish(error); req.resume(); return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (done) return;
      try {
        const text = Buffer.concat(chunks).toString('utf8');
        if (!text) return finish(null, {});
        const result = JSON.parse(text);
        if (!isPlainObject(result)) { const error = new Error('O corpo JSON deve ser um objeto.'); error.statusCode = 400; return finish(error); }
        finish(null, result);
      } catch {
        const error = new Error('JSON inválido.'); error.statusCode = 400; finish(error);
      }
    });
    req.on('error', (error) => finish(error));
    req.setTimeout(12_000, () => { const error = new Error('Tempo limite ao receber a requisição.'); error.statusCode = 408; finish(error); });
  });
}

function normalizeIpAddress(value) {
  const raw = String(value || '').trim();
  const unwrapped = raw.startsWith('[') && raw.includes(']') ? raw.slice(1, raw.indexOf(']')) : raw;
  if (net.isIP(unwrapped) === 4) return unwrapped;
  if (net.isIP(unwrapped) === 6) return unwrapped.toLowerCase().replace(/^::ffff:/, '');
  return null;
}
const TRUSTED_PROXY_IPS = new Set(String(process.env.TRUSTED_PROXY_IPS || '').split(',').map(normalizeIpAddress).filter(Boolean));
function requestIp(req) {
  const remote = normalizeIpAddress(req.socket.remoteAddress);
  if (!remote) return 'Não disponível';
  if (!TRUSTED_PROXY_IPS.has(remote)) return remote;
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',').map(normalizeIpAddress);
  const chain = [...forwarded.filter(Boolean), remote];
  let index = chain.length - 1;
  while (index > 0 && TRUSTED_PROXY_IPS.has(chain[index])) index -= 1;
  return chain[index] || 'Não disponível';
}
function registrationIpHashFromAddress(address) {
  const normalized = normalizeIpAddress(address);
  if (!normalized) return null;
  return crypto.createHmac('sha256', REGISTRATION_IP_HMAC_KEY).update(normalized).digest('hex');
}
function registrationIpHash(req) {
  if (!REGISTRATION_IP_LIMIT_ENABLED) return null;
  const resolved = requestIp(req);
  return registrationIpHashFromAddress(resolved);
}
function premiumTrialEmailHash(email) {
  const normalized = normalizeEmail(email);
  if (!normalized) return null;
  return crypto.createHmac('sha256', REGISTRATION_IP_HMAC_KEY)
    .update('granaclara-premium-trial-eligibility-v1:').update(normalized).digest('hex');
}
function grantPremiumTrialEligibility(email, stamp = nowISO()) {
  const emailHash = premiumTrialEmailHash(email);
  if (!emailHash) throw new Error('Não foi possível registrar a elegibilidade do teste Premium.');
  const expiresAt = new Date(Date.parse(stamp) + PREMIUM_TRIAL_ELIGIBILITY_RETENTION_DAYS * 86400000).toISOString();
  const existing = DB.prepare('SELECT expires_at FROM premium_trial_eligibility WHERE email_hash = ?').get(emailHash);
  if (existing && existing.expires_at > stamp) return false;
  DB.prepare(`INSERT INTO premium_trial_eligibility(email_hash, granted_at, expires_at, policy_version)
    VALUES (?, ?, ?, 'premium-trial-7d-v1')
    ON CONFLICT(email_hash) DO UPDATE SET granted_at=excluded.granted_at, expires_at=excluded.expires_at, policy_version=excluded.policy_version`)
    .run(emailHash, stamp, expiresAt);
  return true;
}
function seedExistingPremiumTrialEligibility() {
  const stamp = nowISO();
  const expiresAt = new Date(Date.now() + PREMIUM_TRIAL_ELIGIBILITY_RETENTION_DAYS * 86400000).toISOString();
  const insert = DB.prepare(`INSERT OR IGNORE INTO premium_trial_eligibility(email_hash, granted_at, expires_at, policy_version)
    VALUES (?, ?, ?, 'premium-trial-7d-v1')`);
  for (const row of DB.prepare("SELECT email FROM users WHERE plan = 'premium'").all()) {
    const emailHash = premiumTrialEmailHash(row.email);
    if (emailHash) insert.run(emailHash, stamp, expiresAt);
  }
}
function activeRegistrationCooldown(req, stamp = nowISO()) {
  const ipHash = registrationIpHashFromAddress(requestIp(req));
  if (!ipHash) return { blocked: false, unavailable: true, remainingSeconds: 0 };
  const row = DB.prepare('SELECT blocked_until FROM registration_attempt_cooldowns WHERE ip_hash = ?').get(ipHash);
  if (!row?.blocked_until || Date.parse(row.blocked_until) <= Date.parse(stamp)) return { blocked: false, unavailable: false, remainingSeconds: 0 };
  return { blocked: true, unavailable: false, remainingSeconds: Math.max(1, Math.ceil((Date.parse(row.blocked_until) - Date.parse(stamp)) / 1000)) };
}
function registrationCooldownState(req, stamp = nowISO(), withinTransaction = false) {
  const ipHash = registrationIpHashFromAddress(requestIp(req));
  if (!ipHash) return { blocked: false, unavailable: true, remainingSeconds: 0 };
  const stampMs = Date.parse(stamp);
  if (!withinTransaction) DB.exec('BEGIN IMMEDIATE');
  try {
    const row = DB.prepare('SELECT * FROM registration_attempt_cooldowns WHERE ip_hash = ?').get(ipHash);
    let windowStartedAt = row?.window_started_at || stamp;
    let attempts = Number(row?.attempts || 0);
    let violations = Number(row?.violation_count || 0);
    let blockedUntil = row?.blocked_until || null;
    if (blockedUntil && Date.parse(blockedUntil) > stampMs) {
      if (!withinTransaction) DB.exec('COMMIT');
      return { blocked: true, unavailable: false, remainingSeconds: Math.max(1, Math.ceil((Date.parse(blockedUntil) - stampMs) / 1000)) };
    }
    if (row && stampMs - Date.parse(windowStartedAt) >= REGISTRATION_ATTEMPT_WINDOW_MS) {
      windowStartedAt = stamp; attempts = 0; violations = 0; blockedUntil = null;
    } else if (blockedUntil && Date.parse(blockedUntil) <= stampMs) {
      // Após o fim do atraso, começa uma nova rodada, preservando o nível da penalidade.
      attempts = 0; blockedUntil = null;
    }
    attempts += 1;
    if (attempts > REGISTRATION_ATTEMPT_THRESHOLD) {
      const seconds = violations === 0 ? 7 : 10;
      violations = Math.min(2, violations + 1);
      attempts = 0;
      blockedUntil = new Date(stampMs + seconds * 1000).toISOString();
    }
    DB.prepare(`INSERT INTO registration_attempt_cooldowns(ip_hash, window_started_at, attempts, violation_count, blocked_until, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(ip_hash) DO UPDATE SET window_started_at=excluded.window_started_at, attempts=excluded.attempts,
      violation_count=excluded.violation_count, blocked_until=excluded.blocked_until, updated_at=excluded.updated_at`)
      .run(ipHash, windowStartedAt, attempts, violations, blockedUntil, stamp);
    if (!withinTransaction) DB.exec('COMMIT');
    if (blockedUntil && Date.parse(blockedUntil) > stampMs) return { blocked: true, unavailable: false, remainingSeconds: Math.max(1, Math.ceil((Date.parse(blockedUntil) - stampMs) / 1000)) };
    return { blocked: false, unavailable: false, remainingSeconds: 0 };
  } catch (error) {
    if (!withinTransaction) { try { DB.exec('ROLLBACK'); } catch {} }
    throw error;
  }
}
function sendRegistrationCooldownError(res, state) {
  res.setHeader('Retry-After', String(state.remainingSeconds));
  sendError(res, 429, `Detectamos várias tentativas de cadastro. Aguarde ${state.remainingSeconds} segundo(s) antes de tentar novamente.`, {
    code: 'REGISTRATION_ATTEMPTS_COOLDOWN', retryAfterSeconds: state.remainingSeconds
  });
}
function registrationIpEncryptionKey() {
  return crypto.createHash('sha256').update('granaclara-registration-ip-encryption-v1:').update(REGISTRATION_IP_HMAC_KEY).digest();
}
function encryptRegistrationIp(address) {
  const normalized = normalizeIpAddress(address);
  if (!normalized) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', registrationIpEncryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(normalized, 'utf8'), cipher.final()]);
  return JSON.stringify({ v: 1, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: ciphertext.toString('base64') });
}
function decryptRegistrationIp(value) {
  if (!value) return null;
  try {
    const record = JSON.parse(value);
    if (record.v !== 1) return null;
    const decipher = crypto.createDecipheriv('aes-256-gcm', registrationIpEncryptionKey(), Buffer.from(record.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(record.tag, 'base64'));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(record.data, 'base64')), decipher.final()]).toString('utf8');
    return normalizeIpAddress(plaintext);
  } catch { return null; }
}
function expireRegistrationIpReleases() {
  const stamp = nowISO();
  DB.prepare(`UPDATE registration_ip_releases SET status='exhausted', updated_at=?
    WHERE status='active' AND remaining_uses > 0 AND expires_at IS NOT NULL AND expires_at <= ?`).run(stamp, stamp);
}
function expirePremiumTrials() {
  const stamp = nowISO();
  DB.exec('BEGIN IMMEDIATE');
  try {
    DB.prepare(`UPDATE payment_subscriptions SET status='past_due', updated_at=? WHERE status='trialing' AND trial_ends_at IS NOT NULL AND trial_ends_at <= ?`).run(stamp, stamp);
    DB.prepare(`UPDATE users SET plan='base', plan_status='expired', plan_started_at=NULL, plan_expires_at=NULL,
      premium_subscription_status=CASE WHEN premium_subscription_status='cancel_scheduled' THEN 'canceled' ELSE 'past_due' END, updated_at=?
      WHERE plan='premium' AND premium_trial_ends_at IS NOT NULL AND premium_trial_ends_at <= ?
      AND premium_subscription_status IN ('trialing','cancel_scheduled')`).run(stamp, stamp);
    DB.exec('COMMIT');
  } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
}
function invalidRegistrationFingerprint(body) {
  const normalized = {
    fullName: typeof body?.fullName === 'string' ? normalizeFullName(body.fullName).slice(0, 200) : String(body?.fullName ?? '').slice(0, 200),
    email: typeof body?.email === 'string' ? normalizeEmail(body.email).slice(0, 254) : String(body?.email ?? '').slice(0, 254),
    password: typeof body?.password === 'string' ? body.password.slice(0, 128) : String(body?.password ?? '').slice(0, 128),
    confirmPassword: typeof body?.confirmPassword === 'string' ? body.confirmPassword.slice(0, 128) : String(body?.confirmPassword ?? '').slice(0, 128)
  };
  return crypto.createHmac('sha256', REGISTRATION_IP_HMAC_KEY).update('invalid-registration-v1:').update(JSON.stringify(normalized)).digest('hex');
}
function registerInvalidRegistrationAttempt(body) {
  const fingerprint = invalidRegistrationFingerprint(body);
  const stamp = nowISO();
  const expires = new Date(Date.now() + 30 * 60_000).toISOString();
  DB.exec('BEGIN IMMEDIATE');
  try {
    DB.prepare('DELETE FROM registration_invalid_form_attempts WHERE expires_at <= ?').run(stamp);
    const previous = DB.prepare('SELECT attempts FROM registration_invalid_form_attempts WHERE fingerprint_hash=? AND expires_at>?').get(fingerprint, stamp);
    const attempts = Math.min(100, Number(previous?.attempts || 0) + 1);
    DB.prepare(`INSERT INTO registration_invalid_form_attempts(fingerprint_hash,attempts,first_attempt_at,last_attempt_at,expires_at)
      VALUES (?,?,?,?,?) ON CONFLICT(fingerprint_hash) DO UPDATE SET attempts=excluded.attempts,last_attempt_at=excluded.last_attempt_at,expires_at=excluded.expires_at`)
      .run(fingerprint, attempts, previous ? (DB.prepare('SELECT first_attempt_at FROM registration_invalid_form_attempts WHERE fingerprint_hash=?').get(fingerprint)?.first_attempt_at || stamp) : stamp, stamp, expires);
    DB.exec('COMMIT');
    return { attempts, blocked: attempts >= 3 };
  } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
}
function clearInvalidRegistrationAttempt(body) {
  DB.prepare('DELETE FROM registration_invalid_form_attempts WHERE fingerprint_hash=?').run(invalidRegistrationFingerprint(body));
}

function registrationIpGate(req) {
  expireRegistrationIpReleases();
  if (!REGISTRATION_IP_LIMIT_ENABLED) return { enabled: false, ipHash: null, blocked: false, unavailable: false, count: 0, releaseId: null };
  const ipHash = registrationIpHash(req);
  if (!ipHash) return { enabled: true, ipHash: null, blocked: false, unavailable: true, count: 0, releaseId: null };
  const counter = DB.prepare('SELECT successful_creations FROM registration_ip_counters WHERE ip_hash = ?').get(ipHash);
  const count = Number(counter?.successful_creations || 0);
  const release = count >= 3 ? DB.prepare(`SELECT id, remaining_uses FROM registration_ip_releases
    WHERE ip_hash = ? AND status = 'active' AND remaining_uses > 0 AND (expires_at IS NULL OR expires_at > ?)
    ORDER BY created_at DESC LIMIT 1`).get(ipHash, nowISO()) : null;
  return { enabled: true, ipHash, blocked: count >= 3 && !release, unavailable: false, count, releaseId: release?.id || null, remainingUses: Number(release?.remaining_uses || 0) };
}
function purgeExpiredDeletedAccounts() {
  const stamp = nowISO();
  return DB.prepare('DELETE FROM deleted_accounts WHERE expires_at <= ?').run(stamp).changes;
}
// Aplica a política de retenção também ao iniciar o servidor, sem depender da
// abertura manual da tela Lixeira para remover registros já vencidos.
purgeExpiredDeletedAccounts();
function registrationIpBlockedResponse(res, gate) {
  if (gate.unavailable) {
    sendError(res, 503, 'Não foi possível verificar o endereço de conexão com segurança. Tente novamente ou procure o suporte.', { code: 'REGISTRATION_IP_UNAVAILABLE' });
    return true;
  }
  if (gate.blocked) {
    sendError(res, 429, 'Limite de criação de contas atingido. Este endereço de conexão já foi utilizado para criar o número máximo de três contas permitido. Entre em uma conta existente ou procure o suporte para analisar um possível bloqueio legítimo.', { code: 'REGISTRATION_IP_LIMIT_REACHED', limit: 3 });
    return true;
  }
  return false;
}
// Marca elegibilidade histórica antes que uma conta Premium antiga possa ser excluída.
seedExistingPremiumTrialEligibility();
expirePremiumTrials();
expireRegistrationIpReleases();

function pruneUserAccessLogs() {
  const cutoff = new Date(Date.now() - ACCESS_LOG_RETENTION_DAYS * 86400000).toISOString();
  DB.prepare('DELETE FROM user_access_logs WHERE accessed_at < ?').run(cutoff);
  DB.prepare("UPDATE users SET last_login_ip = NULL WHERE last_login_at IS NOT NULL AND last_login_at < ?").run(cutoff);
}
function recordUserAccess(userId, req) {
  const stamp = nowISO();
  const ip = requestIp(req);
  DB.exec('BEGIN IMMEDIATE');
  try {
    DB.prepare('INSERT INTO user_access_logs(id, user_id, accessed_at, ip_address) VALUES (?, ?, ?, ?)')
      .run(crypto.randomUUID(), userId, stamp, ip);
    DB.prepare(`UPDATE users SET first_login_at = COALESCE(first_login_at, ?), last_login_at = ?, last_login_ip = ?, updated_at = updated_at WHERE id = ?`)
      .run(stamp, stamp, ip, userId);
    DB.exec('COMMIT');
  } catch (error) {
    try { DB.exec('ROLLBACK'); } catch {}
    throw error;
  }
  pruneUserAccessLogs();
}
pruneUserAccessLogs();
function isRateLimited(req, pathname) {
  const config = RATE_CONFIG[pathname] || RATE_CONFIG.default;
  const key = `${requestIp(req)}:${pathname}`;
  const now = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket || now - bucket.startedAt >= config.window) bucket = { startedAt: now, count: 0 };
  bucket.count += 1;
  rateBuckets.set(key, bucket);
  if (rateBuckets.size > 4000) {
    for (const [k, value] of rateBuckets) if (now - value.startedAt > RATE_WINDOW_MS * 2) rateBuckets.delete(k);
  }
  return bucket.count > config.limit;
}

function normalizeHexColorServer(value) {
  if (typeof value !== 'string' || !/^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/i.test(value)) return null;
  const upper = value.toUpperCase();
  return upper.length === 4 ? `#${upper[1]}${upper[1]}${upper[2]}${upper[2]}${upper[3]}${upper[3]}` : upper;
}
function readThemeSurfaces(raw) {
  let parsed = {};
  try { parsed = typeof raw === 'string' ? JSON.parse(raw) : (isPlainObject(raw) ? raw : {}); } catch { parsed = {}; }
  const result = {};
  for (const key of THEME_SURFACE_KEYS) {
    const color = normalizeHexColorServer(parsed?.[key]);
    if (color) result[key] = color;
  }
  return result;
}
function validateCheckoutBilling(value, accountEmail) {
  if (!isPlainObject(value) || !hasOnlyKeys(value, ['fullName', 'email', 'phone', 'cep', 'street', 'number', 'district', 'city', 'state', 'complement'])) return 'Os dados de cobrança estão incompletos ou contêm campos não permitidos.';
  const text = (key, max, required = true) => typeof value[key] === 'string' && value[key].length <= max && (!required || value[key].trim().length > 0);
  const letters = /^\p{L}+(?: \p{L}+)*$/u;
  const street = /^[\p{L} .,’'ºª#/-]+$/u;
  const complement = /^[\p{L}\p{N}\s.,’'ºª#/-]*$/u;
  if (!text('fullName', 120) || !isValidFullName(value.fullName)) return 'Informe o nome completo usando letras e espaços.';
  if (!text('email', 254) || normalizeEmail(value.email) !== normalizeEmail(accountEmail) || !isValidEmailAddress(value.email)) return 'O e-mail deve corresponder ao e-mail utilizado no cadastro.';
  if (!text('phone', 11) || !/^\d{10,11}$/.test(value.phone)) return 'Informe o telefone somente com 10 ou 11 números.';
  if (!text('cep', 8) || !/^\d{8}$/.test(value.cep)) return 'Informe o CEP com oito números.';
  if (!text('street', 120) || !street.test(value.street)) return 'Informe uma rua válida.';
  if (!text('number', 8) || !/^\d{1,8}$/.test(value.number)) return 'Informe o número da residência somente com números.';
  if (!text('district', 80) || !letters.test(value.district)) return 'Informe um bairro usando letras e espaços.';
  if (!text('city', 80) || !letters.test(value.city)) return 'Informe uma cidade usando letras e espaços.';
  if (!text('state', 40) || !letters.test(value.state)) return 'Informe um estado usando letras.';
  if (!text('complement', 120, false) || !complement.test(value.complement)) return 'Revise o complemento do endereço.';
  return null;
}

function safePublicUser(row) {
  return {
    id: row.id, fullName: row.full_name, email: row.email,
    monthlyIncomeCents: row.monthly_income_cents, monthlyBudgetCents: row.monthly_budget_cents,
    plan: Plans.planFor(row.plan), createdAt: row.created_at,
    planStatus: row.premium_subscription_status === 'local_access' ? 'local' : (row.plan_status || (row.plan === 'premium' ? 'legacy' : 'free')),
    planStartedAt: row.plan_started_at || null, planExpiresAt: row.plan_expires_at || null,
    premiumTrialStartedAt: row.premium_trial_started_at || null,
    premiumTrialEndsAt: row.premium_trial_ends_at || null,
    premiumFirstBillingAt: row.premium_first_billing_at || null,
    premiumFirstBillingPeriodEndsAt: row.premium_first_billing_period_ends_at || null,
    premiumTrialConsentAt: row.premium_trial_consent_at || null,
    premiumTrialCancelRequestedAt: row.premium_trial_cancel_requested_at || null,
    premiumSubscriptionStatus: row.premium_subscription_status || 'none',
    premiumProviderSubscriptionId: row.premium_provider_subscription_id || null,
    premiumNextPaymentAt: row.premium_next_payment_at || null,
    premiumPaymentMethodLast4: row.premium_payment_method_last4 || null,
    premiumPaymentMethodBrand: row.premium_payment_method_brand || null,
    loginLockedUntil: adminLoginLockedUntil(row),
    hideExpiryNotice: Boolean(row.hide_expiry_notice),
    demoTwoFactorEnabled: Boolean(row.demo_two_factor_enabled),
    themeAccent: /^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/i.test(String(row.theme_accent || '')) ? row.theme_accent : '#4BD3A2',
    themeSurfaces: readThemeSurfaces(row.theme_surfaces),
    hasProfilePhoto: Boolean(row.profile_photo),
    profilePhotoUpdatedAt: row.profile_photo_updated_at || null
  };
}
function sessionForRequest(req) {
  const token = parseCookie(req, 'ct_session');
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
  const tokenHash = hashToken(token);
  let row = DB.prepare(`SELECT s.token_hash, s.csrf_token, s.expires_at, u.*
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > ?`).get(tokenHash, nowISO());
  if (!row || row.account_status === 'deactivated') {
    DB.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash);
    return null;
  }
  const currentTime = nowISO();
  const trialExpired = row.premium_trial_ends_at && row.premium_trial_ends_at <= currentTime
    && ['trialing', 'cancel_scheduled'].includes(row.premium_subscription_status);
  const legacyDemoExpired = row.plan === 'premium' && row.plan_status === 'demo' && !row.premium_trial_ends_at
    && row.plan_expires_at && row.plan_expires_at <= currentTime;
  if (row.plan === 'premium' && trialExpired) {
    const terminalStatus = row.premium_subscription_status === 'cancel_scheduled' ? 'canceled' : 'past_due';
    DB.exec('BEGIN IMMEDIATE');
    try {
      DB.prepare(`UPDATE users SET plan='base', plan_status='expired', plan_started_at=NULL, plan_expires_at=NULL,
        premium_subscription_status=?, updated_at=? WHERE id=? AND plan='premium' AND premium_trial_ends_at <= ?`)
        .run(terminalStatus, currentTime, row.id, currentTime);
      if (terminalStatus === 'past_due') DB.prepare(`UPDATE payment_subscriptions SET status='past_due', updated_at=? WHERE user_id=? AND status='trialing' AND trial_ends_at <= ?`).run(currentTime, row.id, currentTime);
      DB.exec('COMMIT');
    } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
    row = DB.prepare(`SELECT s.token_hash, s.csrf_token, s.expires_at, u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`).get(tokenHash, currentTime);
  } else if (legacyDemoExpired) {
    DB.prepare(`UPDATE users SET plan='base', plan_status='expired', plan_started_at=NULL, plan_expires_at=NULL, premium_subscription_status='legacy_demo_expired', updated_at=?
      WHERE id=? AND plan='premium' AND plan_status='demo' AND plan_expires_at <= ?`).run(currentTime, row.id, currentTime);
    row = DB.prepare(`SELECT s.token_hash, s.csrf_token, s.expires_at, u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`).get(tokenHash, currentTime);
  }
  DB.prepare('UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?').run(nowISO(), tokenHash);
  return { tokenHash, csrfToken: row.csrf_token, user: row, publicUser: safePublicUser(row) };
}
function requireSession(req, res) {
  const session = sessionForRequest(req);
  if (!session) sendError(res, 401, 'Entre na sua conta para continuar.');
  return session;
}
function checkMutationProtection(req, res, session, options = {}) {
  if (!originIsAllowed(req)) { sendError(res, 403, 'Origem da requisição não autorizada.'); return false; }
  if (options.publicAuth) return true;
  if (!session) { sendError(res, 401, 'Entre na sua conta para continuar.'); return false; }
  const supplied = req.headers['x-csrf-token'];
  if (!timingSafeString(String(supplied || ''), session.csrfToken)) { sendError(res, 403, 'Token de segurança inválido. Atualize a página e tente novamente.'); return false; }
  return true;
}
function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const csrfToken = crypto.randomBytes(32).toString('hex');
  const created = new Date();
  const expires = new Date(created.getTime() + SESSION_MS);
  DB.prepare('INSERT INTO sessions(token_hash, user_id, csrf_token, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(hashToken(token), userId, csrfToken, created.toISOString(), expires.toISOString(), created.toISOString());
  return { token, csrfToken, expiresAt: expires.toISOString() };
}

function createAdminSession(adminUserId) {
  const token = crypto.randomBytes(32).toString('hex');
  const csrfToken = crypto.randomBytes(32).toString('hex');
  const created = new Date();
  const expires = new Date(created.getTime() + ADMIN_SESSION_MS);
  DB.prepare('INSERT INTO admin_sessions(token_hash, admin_user_id, csrf_token, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(hashToken(token), adminUserId, csrfToken, created.toISOString(), expires.toISOString(), created.toISOString());
  return { token, csrfToken, expiresAt: expires.toISOString() };
}
function adminSessionForRequest(req) {
  const token = parseCookie(req, 'gc_admin_session');
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
  const tokenHash = hashToken(token);
  const row = DB.prepare(`SELECT s.token_hash, s.csrf_token, s.expires_at, s.reauthenticated_at, a.id, a.full_name, a.email,
      a.role, a.must_change_password, a.profile_configured, a.is_active
    FROM admin_sessions s JOIN admin_users a ON a.id = s.admin_user_id
    WHERE s.token_hash = ? AND s.expires_at > ? AND a.is_active = 1 AND a.role = 'admin'`).get(tokenHash, nowISO());
  if (!row) {
    DB.prepare('DELETE FROM admin_sessions WHERE token_hash = ?').run(tokenHash);
    return null;
  }
  DB.prepare('UPDATE admin_sessions SET last_seen_at = ? WHERE token_hash = ?').run(nowISO(), tokenHash);
  return {
    tokenHash, csrfToken: row.csrf_token, expiresAt: row.expires_at, reauthenticatedAt: row.reauthenticated_at || null,
    admin: { id: row.id, fullName: row.full_name, email: row.email, role: row.role },
    mustChangePassword: Boolean(row.must_change_password), mustCompleteProfile: !Boolean(row.profile_configured)
  };
}
function requireAdminSession(req, res, options = {}) {
  const session = adminSessionForRequest(req);
  if (!session) { sendError(res, 401, 'Acesso administrativo necessário.'); return null; }
  if ((session.mustChangePassword || session.mustCompleteProfile) && !options.allowPasswordChange) {
    sendError(res, 403, 'Conclua a configuração inicial do perfil administrativo para continuar.', { code: 'ADMIN_PASSWORD_CHANGE_REQUIRED', mustChangePassword: true, mustCompleteProfile: session.mustCompleteProfile });
    return null;
  }
  return session;
}
function checkAdminMutationProtection(req, res, session) {
  if (!originIsAllowed(req)) { sendError(res, 403, 'Origem da requisição não autorizada.'); return false; }
  if (!session) { sendError(res, 401, 'Acesso administrativo necessário.'); return false; }
  if (!timingSafeString(String(req.headers['x-csrf-token'] || ''), session.csrfToken)) {
    sendError(res, 403, 'Token de segurança administrativo inválido. Atualize a página.');
    return false;
  }
  return true;
}
async function verifyAdminPassword(password, saltHex, hashHex) {
  try {
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(hashHex, 'hex');
    if (!salt.length || expected.length !== 64) return false;
    const actual = await scryptAsync(password, salt, expected.length, { N: 32768, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
    return crypto.timingSafeEqual(actual, expected);
  } catch { return false; }
}
async function hashAdminPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = await scryptAsync(password, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  return { salt: salt.toString('hex'), hash: derived.toString('hex') };
}
function writeAdminAudit(session, action, targetUserId = null, details = {}, req = null) {
  DB.prepare(`INSERT INTO admin_audit_logs(id, admin_user_id, action, target_user_id, details_json, ip_address, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)`).run(
    crypto.randomUUID(), session.admin.id, action, targetUserId,
    JSON.stringify(details && typeof details === 'object' ? details : {}),
    req ? requestIp(req) : '', nowISO()
  );
}
function paymentStatusForUser(row) {
  if (row.account_status === 'deactivated') return 'Conta desativada';
  if (row.plan === 'base') return 'Base — gratuito';
  if (row.premium_subscription_status === 'local_access') return 'Premium — acesso local';
  if (row.plan_status === 'legacy') return 'Premium ativo';
  if (['trialing','cancel_scheduled'].includes(row.premium_subscription_status) && row.premium_trial_ends_at) {
    return row.premium_subscription_status === 'cancel_scheduled'
      ? `Teste cancelado até ${row.premium_trial_ends_at}`
      : `Teste gratuito até ${row.premium_trial_ends_at}`;
  }
  const latestPayment = DB.prepare('SELECT status, due_at FROM payment_records WHERE user_id = ? ORDER BY created_at DESC LIMIT 1').get(row.id);
  if (latestPayment) {
    if (latestPayment.status === 'paid') return 'Pagamento efetuado';
    if (latestPayment.status === 'canceled') return 'Assinatura cancelada';
    if (latestPayment.status === 'refunded') return 'Pagamento reembolsado';
    if (latestPayment.status === 'charged_back') return 'Pagamento contestado';
    if (latestPayment.status === 'rejected') return 'Pagamento recusado';
    if (latestPayment.status === 'overdue' || (latestPayment.status === 'pending' && latestPayment.due_at && latestPayment.due_at < nowISO())) return 'Pagamento atrasado';
    return 'Pagamento pendente';
  }
  if (row.premium_subscription_status === 'pending') return 'Aguardando autorização do pagamento';
  if (row.premium_subscription_status === 'past_due') return 'Pagamento atrasado';
  if (row.premium_subscription_status === 'canceled') return 'Assinatura cancelada';
  if (row.plan_status === 'legacy' || row.plan_status === 'demo') return 'Premium anterior — sem pagamento confirmado';
  return 'Premium — pagamento não confirmado';
}

function adminPublicClient(row) {
  return {
    id: row.id, fullName: row.full_name, email: row.email,
    plan: Plans.planFor(row.plan), planStatus: row.premium_subscription_status === 'local_access' ? 'local' : (row.plan_status || (row.plan === 'premium' ? 'legacy' : 'free')),
    planStartedAt: row.plan_started_at || null, planExpiresAt: row.plan_expires_at || null,
    accountStatus: row.account_status || 'active', createdAt: row.created_at,
    loginLockedUntil: adminLoginLockedUntil(row),
    loginLockStartedAt: row.login_lock_started_at || null,
    paymentStatus: paymentStatusForUser(row),
    valueCents: null
  };
}
function parseAdminClientId(pathname) {
  const match = pathname.match(/^\/api\/admin\/clients\/([0-9a-f-]{36})$/i);
  return match ? match[1] : null;
}
function detachAccountGroupsForDeactivation(userId) {
  const ownedGroups = DB.prepare('SELECT id FROM account_link_groups WHERE owner_user_id = ?').all(userId);
  let otherAccountsUnlinked = 0;
  for (const group of ownedGroups) {
    otherAccountsUnlinked += Number(DB.prepare('SELECT COUNT(*) AS n FROM account_link_members WHERE group_id = ? AND user_id <> ?').get(group.id, userId).n);
    // O grupo deixa de existir, mas nenhuma conta nem dado financeiro é removido.
    DB.prepare('DELETE FROM account_link_groups WHERE id = ?').run(group.id);
  }
  const ownMemberships = DB.prepare('DELETE FROM account_link_members WHERE user_id = ?').run(userId).changes;
  return { ownedGroupsRemoved: ownedGroups.length, otherAccountsUnlinked, ownMembershipsRemoved: ownMemberships };
}

async function handleAdminApi(req, res, url, pathname, method) {
  if (!pathname.startsWith('/api/admin/')) return false;

  if (pathname === '/api/admin/sync/revision' && method === 'GET') {
    const session = requireAdminSession(req, res);
    if (!session) return true;
    const row = DB.prepare('SELECT revision, updated_at FROM app_sync_state WHERE id=1').get();
    sendJson(res, 200, { revision: Number(row?.revision || 0), updatedAt: row?.updated_at || null });
    return true;
  }

  if (pathname === '/api/admin/auth/session' && method === 'GET') {
    const session = requireAdminSession(req, res, { allowPasswordChange: true });
    if (!session) return true;
    sendJson(res, 200, { authenticated: true, admin: session.admin, csrfToken: session.csrfToken, mustChangePassword: session.mustChangePassword, mustCompleteProfile: session.mustCompleteProfile, expiresAt: session.expiresAt });
    return true;
  }

  if (pathname === '/api/admin/auth/reauth' && method === 'POST') {
    const session = requireAdminSession(req, res);
    if (!session) return true;
    if (!checkAdminMutationProtection(req, res, session)) return true;
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['password']) || !validateText(body.password, 128, true)) {
      sendError(res, 400, 'Informe sua senha administrativa.'); return true;
    }
    if (adminLoginIsLocked(session.admin.email, req)) { res.setHeader('Retry-After', '900'); sendError(res, 429, 'Confirmação administrativa temporariamente bloqueada após tentativas inválidas.'); return true; }
    const row = DB.prepare("SELECT password_salt, password_hash, profile_configured FROM admin_users WHERE id = ? AND role = 'admin' AND is_active = 1").get(session.admin.id);
    if (!row || !(await verifyAdminPassword(body.password, row.password_salt, row.password_hash))) {
      const attempt = registerAdminLoginFailure(session.admin.email, req);
      if (attempt.locked) { res.setHeader('Retry-After', '900'); sendError(res, 429, 'Confirmação administrativa temporariamente bloqueada após tentativas inválidas.'); }
      else sendError(res, 403, 'Senha administrativa incorreta.');
      return true;
    }
    clearAdminLoginFailures(session.admin.email, req);
    const stamp = nowISO();
    DB.prepare('UPDATE admin_sessions SET reauthenticated_at = ?, last_seen_at = ? WHERE token_hash = ?').run(stamp, stamp, session.tokenHash);
    writeAdminAudit(session, 'admin_reauthenticated', null, {}, req);
    sendJson(res, 200, { reauthenticated: true, reauthenticatedAt: stamp });
    return true;
  }

  if (pathname === '/api/admin/auth/password' && method === 'POST') {
    const session = requireAdminSession(req, res, { allowPasswordChange: true });
    if (!session) return true;
    if (!checkAdminMutationProtection(req, res, session)) return true;
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['fullName', 'currentPassword', 'newPassword', 'confirmPassword']) ||
        !validateText(body.fullName, 120, true) || !isValidFullName(normalizeFullName(body.fullName)) ||
        !validateText(body.currentPassword, 128, true) || !validateText(body.newPassword, 128, true) || body.newPassword !== body.confirmPassword) {
      sendError(res, 400, 'Informe nome e sobrenome, senha inicial e confirmação da nova senha.'); return true;
    }
    if (body.newPassword.length < 12 || !/[a-z]/.test(body.newPassword) || !/[A-Z]/.test(body.newPassword) || !/\d/.test(body.newPassword) || !/[^A-Za-z0-9]/.test(body.newPassword)) {
      sendError(res, 400, 'A nova senha precisa ter ao menos 12 caracteres, letra maiúscula, minúscula, número e símbolo.'); return true;
    }
    const row = DB.prepare("SELECT password_salt, password_hash FROM admin_users WHERE id = ? AND role = 'admin' AND is_active = 1").get(session.admin.id);
    if (!row || !(await verifyAdminPassword(body.currentPassword, row.password_salt, row.password_hash))) {
      sendError(res, 403, 'Senha atual incorreta.'); return true;
    }
    const next = await hashAdminPassword(body.newPassword);
    DB.exec('BEGIN IMMEDIATE');
    try {
      const displayName = normalizeFullName(body.fullName);
      DB.prepare('UPDATE admin_users SET full_name=?,password_salt=?,password_hash=?,must_change_password=0,profile_configured=1,updated_at=? WHERE id=?')
        .run(displayName, next.salt, next.hash, nowISO(), session.admin.id);
      // A troca de senha invalida todas as outras sessões administrativas.
      DB.prepare('DELETE FROM admin_sessions WHERE admin_user_id = ? AND token_hash <> ?').run(session.admin.id, session.tokenHash);
      DB.prepare('UPDATE admin_sessions SET reauthenticated_at = ?, last_seen_at = ? WHERE token_hash = ?').run(nowISO(), nowISO(), session.tokenHash);
      writeAdminAudit({ ...session, admin: { ...session.admin, fullName: displayName } }, 'admin_password_changed', null, { forcedInitialChange: session.mustChangePassword, profileConfigured: true, otherSessionsRevoked: true }, req);
      DB.exec('COMMIT');
    } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
    sendJson(res, 200, { changed: true, admin: { ...session.admin, fullName: normalizeFullName(body.fullName) }, message: 'Configuração inicial concluída. O painel administrativo foi liberado.' });
    return true;
  }

  if (pathname === '/api/admin/auth/logout' && method === 'POST') {
    const session = requireAdminSession(req, res, { allowPasswordChange: true });
    if (!session) return true;
    if (!checkAdminMutationProtection(req, res, session)) return true;
    DB.prepare('DELETE FROM admin_sessions WHERE token_hash = ?').run(session.tokenHash);
    writeAdminAudit(session, 'admin_logout', null, {}, req);
    sendJson(res, 200, { ok: true }, { 'Set-Cookie': clearCookie('gc_admin_session') });
    return true;
  }

  const allowPasswordChange = false;
  const session = requireAdminSession(req, res, { allowPasswordChange });
  if (!session) return true;
  DB.prepare(`UPDATE users SET plan = 'base', plan_status = 'expired', plan_started_at = NULL, plan_expires_at = NULL, updated_at = ?
    WHERE plan = 'premium' AND plan_status = 'demo' AND plan_expires_at IS NOT NULL AND plan_expires_at <= ?`).run(nowISO(), nowISO());

  if (pathname === '/api/admin/dashboard' && method === 'GET') {
    const total = Number(DB.prepare("SELECT COUNT(DISTINCT id) AS n FROM users WHERE account_status = 'active'").get().n);
    const base = Number(DB.prepare("SELECT COUNT(DISTINCT id) AS n FROM users WHERE account_status = 'active' AND plan = 'base'").get().n);
    const premium = Number(DB.prepare("SELECT COUNT(DISTINCT id) AS n FROM users WHERE account_status = 'active' AND plan = 'premium'").get().n);
    const premiumLocal = Number(DB.prepare("SELECT COUNT(DISTINCT id) AS n FROM users WHERE account_status = 'active' AND plan = 'premium' AND plan_status = 'legacy' AND premium_subscription_status = 'none'").get().n);
    const trialing = Number(DB.prepare("SELECT COUNT(DISTINCT id) AS n FROM users WHERE account_status = 'active' AND plan = 'premium' AND premium_subscription_status = 'trialing'").get().n);
    const premiumPending = Number(DB.prepare("SELECT COUNT(DISTINCT id) AS n FROM users WHERE account_status = 'active' AND premium_subscription_status IN ('pending','past_due')").get().n);
    const paid = Number(DB.prepare("SELECT COUNT(*) AS n FROM payment_records WHERE status = 'paid'").get().n);
    const pending = Number(DB.prepare("SELECT COUNT(*) AS n FROM payment_records WHERE status = 'pending'").get().n);
    const overdue = Number(DB.prepare("SELECT COUNT(*) AS n FROM payment_records WHERE status = 'overdue' OR (status = 'pending' AND due_at IS NOT NULL AND due_at < ?)").get(nowISO()).n);
    const recentRows = DB.prepare('SELECT * FROM users ORDER BY created_at DESC, id ASC LIMIT 8').all();
    const recent = [...new Map(recentRows.map((row) => [row.id, adminPublicClient(row)])).values()];
    sendJson(res, 200, { totals: { clients: total, base, premium, premiumTrialing: trialing, premiumLocal, premiumPending, paymentsPaid: paid, paymentsPending: pending, paymentsOverdue: overdue, paymentsIntegrated: paymentCheckoutAvailable() }, recent });
    return true;
  }

  if (pathname === '/api/admin/clients' && method === 'GET') {
    const plan = url.searchParams.get('plan');
    if (!['base', 'premium'].includes(plan)) { sendError(res, 400, 'Informe a aba de clientes Base ou Premium.'); return true; }
    const rawPage = Number(url.searchParams.get('page') || 1);
    const rawSize = Number(url.searchParams.get('pageSize') || 20);
    if (!Number.isInteger(rawPage) || rawPage < 1 || !Number.isInteger(rawSize) || rawSize < 1 || rawSize > 100) { sendError(res, 400, 'Paginação inválida.'); return true; }
    const status = url.searchParams.get('status') || 'active';
    if (!['active', 'deactivated', 'all'].includes(status)) { sendError(res, 400, 'Filtro de situação inválido.'); return true; }
    const sort = url.searchParams.get('sort') || 'newest';
    const orderBy = { newest: 'created_at DESC, id ASC', oldest: 'created_at ASC, id ASC', name: 'full_name COLLATE NOCASE ASC, id ASC' }[sort];
    if (!orderBy) { sendError(res, 400, 'Ordenação inválida.'); return true; }
    const q = String(url.searchParams.get('q') || '').trim().slice(0, 120);
    const where = ['plan = ?']; const values = [plan];
    if (status !== 'all') { where.push('account_status = ?'); values.push(status); }
    if (q) { where.push('(full_name LIKE ? COLLATE NOCASE OR email LIKE ? COLLATE NOCASE)'); values.push(`%${q}%`, `%${q}%`); }
    const clause = where.join(' AND ');
    const total = Number(DB.prepare(`SELECT COUNT(*) AS n FROM users WHERE ${clause}`).get(...values).n);
    const pages = Math.max(1, Math.ceil(total / rawSize));
    const page = Math.min(rawPage, pages);
    const items = DB.prepare(`SELECT * FROM users WHERE ${clause} ORDER BY ${orderBy} LIMIT ? OFFSET ?`).all(...values, rawSize, (page - 1) * rawSize).map(adminPublicClient);
    sendJson(res, 200, { items, page, pageSize: rawSize, total, pages, plan });
    return true;
  }

  const loginUnlockMatch = pathname.match(/^\/api\/admin\/clients\/([0-9a-f-]{36})\/login-unlock$/i);
  if (loginUnlockMatch && method === 'POST') {
    if (!checkAdminMutationProtection(req, res, session)) return true;
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['reason']) || typeof body.reason !== 'string' || body.reason.trim().length < 8 || body.reason.trim().length > 500) {
      sendError(res, 400, 'Informe um motivo com pelo menos 8 caracteres para liberar esta conta.'); return true;
    }
    const userId = loginUnlockMatch[1];
    const stamp = nowISO();
    DB.exec('BEGIN IMMEDIATE');
    try {
      const client = DB.prepare("SELECT id,full_name,email,login_locked_until,login_lock_started_at,account_status FROM users WHERE id=?").get(userId);
      if (!client || client.account_status !== 'active') { DB.exec('ROLLBACK'); sendError(res, 404, 'Conta ativa não encontrada.'); return true; }
      const lock = loginLockState(client);
      if (!lock.locked) { DB.exec('ROLLBACK'); sendError(res, 409, 'Esta conta não possui um bloqueio ativo.'); return true; }
      DB.prepare('UPDATE users SET login_locked_until=NULL,login_lock_started_at=NULL,updated_at=? WHERE id=?').run(stamp, userId);
      DB.prepare('DELETE FROM client_login_attempt_buckets WHERE user_id=?').run(userId);
      const reason = body.reason.trim();
      writeAdminAudit(session, 'client_login_unlocked', userId, { reason, lockedUntil: client.login_locked_until }, req);
      DB.prepare(`INSERT INTO user_security_events(id,user_id,event_type,source_ip_hash,details_json,created_at,source_ip_address) VALUES (?,?, 'client_login_unlocked', ?, ?, ?, ?)`)
        .run(crypto.randomUUID(), userId, registrationIpHashFromAddress(requestIp(req)), JSON.stringify({ adminId: session.admin.id, adminName: session.admin.fullName, reason }), stamp, normalizeIpAddress(requestIp(req)));
      DB.exec('COMMIT');
      sendJson(res, 200, { unlocked: true, client: { id: client.id, fullName: client.full_name, email: client.email, loginLockedUntil: null }, message: 'Conta liberada com sucesso.' });
      return true;
    } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
  }

  if (pathname === '/api/admin/payments' && method === 'GET') {
    const users = DB.prepare('SELECT * FROM users ORDER BY full_name COLLATE NOCASE ASC').all();
    const pending = []; const paid = []; const nonBillable = [];
    for (const user of users) {
      const payment = DB.prepare('SELECT provider, due_at, paid_at, status, amount_cents, currency FROM payment_records WHERE user_id = ? ORDER BY created_at DESC LIMIT 1').get(user.id);
      const subscription = DB.prepare('SELECT status, next_payment_at, amount_cents, trial_ends_at FROM payment_subscriptions WHERE user_id=? ORDER BY created_at DESC LIMIT 1').get(user.id);
      let status; let dueAt = payment?.due_at || subscription?.next_payment_at || null;
      if (user.account_status === 'deactivated' || payment?.status === 'canceled') status = 'Assinatura cancelada';
      else if (payment?.status === 'paid') status = 'Pagamento efetuado';
      else if (payment?.status === 'overdue' || (payment?.status === 'pending' && dueAt && dueAt < nowISO())) status = 'Pagamento atrasado';
      else if (payment?.status === 'pending') status = 'Pagamento pendente';
      else if (user.plan === 'base') status = user.premium_subscription_status === 'canceled' ? 'Assinatura cancelada' : 'Base — gratuito';
      else if (user.plan_status === 'legacy' && user.plan === 'premium') status = 'Premium legado — sem assinatura confirmada';
      else if (user.premium_subscription_status === 'trialing' && user.premium_trial_ends_at) { status = 'Assinatura em período gratuito'; dueAt = user.premium_trial_ends_at; }
      else if (user.premium_subscription_status === 'pending') status = 'Aguardando autorização do provedor';
      else if (user.premium_subscription_status === 'past_due') status = 'Pagamento atrasado';
      else status = 'Contratação pendente — sem pagamento confirmado';
      const item = { id: user.id, fullName: user.full_name, email: user.email, dueAt, status, plan: user.plan, amountCents: payment?.amount_cents ?? subscription?.amount_cents ?? (user.plan === 'premium' ? PREMIUM_PRICE_CENTS : null), paymentStatus: payment?.status || null };
      if (status === 'Pagamento pendente' || status === 'Pagamento atrasado') pending.push(item);
      else if (status === 'Pagamento efetuado') paid.push(item);
      else nonBillable.push(item);
    }
    pending.sort((a, b) => (a.status === b.status ? String(a.dueAt || '9999').localeCompare(String(b.dueAt || '9999')) : a.status === 'Pagamento atrasado' ? -1 : 1));
    const paymentConfig = paymentConfiguration();
    const pendingSubscriptions = DB.prepare(`SELECT s.id, s.user_id, s.next_payment_at, s.status, s.amount_cents, u.full_name
      FROM payment_subscriptions s JOIN users u ON u.id=s.user_id WHERE s.status IN ('pending','past_due') AND u.account_status='active' ORDER BY s.next_payment_at ASC`).all();
    for (const sub of pendingSubscriptions) {
      if (!pending.some((item) => item.id === sub.user_id)) {
        const user = DB.prepare('SELECT email FROM users WHERE id=?').get(sub.user_id);
        pending.push({ id: sub.user_id, fullName: sub.full_name, email: user?.email || null, dueAt: sub.next_payment_at, status: sub.status === 'past_due' ? 'Pagamento atrasado' : 'Pagamento pendente', plan: 'premium', amountCents: sub.amount_cents });
      }
    }
    const providerReady = paymentCheckoutAvailable();
    sendJson(res, 200, { pending, paid, nonBillable, gatewayEnabled: providerReady, provider: 'mercadopago', message: providerReady ? 'Status consolidado a partir das confirmações e notificações do provedor.' : 'Checkout indisponível: configure as credenciais, a origem pública HTTPS e o webhook antes de aceitar novas assinaturas.' });
    return true;
  }

  if (pathname === '/api/admin/accesses' && method === 'GET') {
    const rows = DB.prepare(`SELECT u.id, u.full_name, u.last_login_ip, u.first_login_at, u.last_login_at
      FROM users u WHERE u.account_status = 'active' ORDER BY CASE WHEN u.last_login_at IS NULL THEN 1 ELSE 0 END, u.last_login_at DESC, u.full_name COLLATE NOCASE ASC`).all();
    writeAdminAudit(session, 'client_access_list_viewed', null, { clientCount: rows.length }, req);
    sendJson(res, 200, { items: rows.map((row) => ({ id: row.id, fullName: row.full_name, lastLoginIp: row.last_login_ip || 'Não disponível', firstAccessAt: row.first_login_at || null, lastAccessAt: row.last_login_at || null })), retentionDays: ACCESS_LOG_RETENTION_DAYS });
    return true;
  }

  if (pathname === '/api/admin/registration-ip-releases' && method === 'GET') {
    expireRegistrationIpReleases();
    const q = String(url.searchParams.get('q') || '').trim().slice(0, 80).toLowerCase();
    const rawPage = Number(url.searchParams.get('page') || 1);
    const rawSize = Number(url.searchParams.get('pageSize') || 20);
    if (!Number.isInteger(rawPage) || rawPage < 1 || !Number.isInteger(rawSize) || rawSize < 1 || rawSize > 100) { sendError(res, 400, 'Paginação inválida.'); return true; }
    const rows = DB.prepare(`SELECT r.*, c.successful_creations
      FROM registration_ip_releases r
      LEFT JOIN registration_ip_counters c ON c.ip_hash = r.ip_hash
      WHERE r.status = 'active' AND r.remaining_uses > 0 AND (r.expires_at IS NULL OR r.expires_at > ?)
      ORDER BY r.created_at DESC`).all(nowISO());
    const filtered = rows.map((row) => {
      const ip = decryptRegistrationIp(row.encrypted_ip) || 'IP legado não recuperável';
      return { id: row.id, ip, ipRecoverable: ip !== 'IP legado não recuperável', reason: row.reason,
        createdAt: row.created_at, expiresAt: row.expires_at || null, remainingUses: Number(row.remaining_uses),
        successfulCreations: Number(row.successful_creations || 0), limit: 3, adminName: row.approved_by_admin_name };
    }).filter((item) => !q || item.ip.toLowerCase().includes(q));
    const pages = Math.max(1, Math.ceil(filtered.length / rawSize));
    const page = Math.min(rawPage, pages);
    const items = filtered.slice((page - 1) * rawSize, page * rawSize);
    sendJson(res, 200, { items, page, pageSize: rawSize, total: filtered.length, pages, activeCount: filtered.length, limit: 3 });
    return true;
  }

  if (pathname === '/api/admin/registration-ip-releases' && method === 'POST') {
    if (!checkAdminMutationProtection(req, res, session)) return true;
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['ip', 'reason']) || typeof body.ip !== 'string' || typeof body.reason !== 'string') {
      sendError(res, 400, 'Informe o endereço IP e o motivo da liberação.'); return true;
    }
    const ip = normalizeIpAddress(body.ip);
    const reason = body.reason.trim();
    if (!ip) { sendError(res, 400, 'Informe um endereço IPv4 ou IPv6 válido.'); return true; }
    if (reason.length < 5 || reason.length > 500) { sendError(res, 400, 'O motivo é obrigatório e deve conter entre 5 e 500 caracteres.'); return true; }
    const ipHash = registrationIpHashFromAddress(ip);
    if (!ipHash) { sendError(res, 400, 'Não foi possível identificar esse endereço IP.'); return true; }
    const stamp = nowISO();
    const releaseId = crypto.randomUUID();
    DB.exec('BEGIN IMMEDIATE');
    try {
      const counter = DB.prepare('SELECT successful_creations FROM registration_ip_counters WHERE ip_hash = ?').get(ipHash);
      if (!counter || Number(counter.successful_creations) < 3) {
        DB.exec('ROLLBACK');
        sendError(res, 409, 'Este endereço IP ainda não atingiu o limite de três criações.'); return true;
      }
      const active = DB.prepare(`SELECT id FROM registration_ip_releases WHERE ip_hash = ? AND status = 'active' AND remaining_uses > 0 AND (expires_at IS NULL OR expires_at > ?)`).get(ipHash, stamp);
      if (active) {
        DB.exec('ROLLBACK');
        sendError(res, 409, 'Este endereço IP já possui uma liberação ativa.'); return true;
      }
      DB.prepare(`INSERT INTO registration_ip_releases
        (id, ip_hash, encrypted_ip, remaining_uses, status, reason, approved_by_admin_id, approved_by_admin_name, created_at, updated_at, expires_at)
        VALUES (?, ?, ?, 3, 'active', ?, ?, ?, ?, ?, ?)`)
        .run(releaseId, ipHash, encryptRegistrationIp(ip), reason, session.admin.id, session.admin.fullName, stamp, stamp, new Date(Date.parse(stamp) + 7 * 86400000).toISOString());
      writeAdminAudit(session, 'registration_ip_release_granted', null, { releaseId, ipHash, reason, authorizedCreations: 3 }, req);
      DB.exec('COMMIT');
    } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
    sendJson(res, 201, { id: releaseId, granted: true, remainingUses: 3, expiresAt: new Date(Date.parse(stamp) + 7 * 86400000).toISOString(), message: 'Endereço IP liberado com sucesso por 7 dias.' });
    return true;
  }

  const ipReleaseMatch = pathname.match(/^\/api\/admin\/registration-ip-releases\/([0-9a-f-]{36})(?:\/(cancel))?$/i);
  if (ipReleaseMatch) {
    const releaseId = ipReleaseMatch[1];
    if (method === 'PATCH' && !ipReleaseMatch[2]) {
      if (!checkAdminMutationProtection(req, res, session)) return true;
      const body = await readJson(req);
      if (!isPlainObject(body) || !hasOnlyKeys(body, ['reason']) || typeof body.reason !== 'string') { sendError(res, 400, 'Informe o motivo atualizado.'); return true; }
      const reason = body.reason.trim();
      if (reason.length < 5 || reason.length > 500) { sendError(res, 400, 'O motivo deve conter entre 5 e 500 caracteres.'); return true; }
      DB.exec('BEGIN IMMEDIATE');
      try {
        const row = DB.prepare(`SELECT id, ip_hash, reason FROM registration_ip_releases WHERE id = ? AND status = 'active' AND remaining_uses > 0`).get(releaseId);
        if (!row) { DB.exec('ROLLBACK'); sendError(res, 404, 'Liberação ativa não encontrada.'); return true; }
        DB.prepare('UPDATE registration_ip_releases SET reason = ?, updated_at = ? WHERE id = ? AND status = \'active\'').run(reason, nowISO(), releaseId);
        writeAdminAudit(session, 'registration_ip_release_reason_changed', null, { releaseId, ipHash: row.ip_hash, previousReason: row.reason, reason }, req);
        DB.exec('COMMIT');
      } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
      sendJson(res, 200, { updated: true, message: 'Motivo da liberação atualizado com sucesso.' });
      return true;
    }
    if (method === 'POST' && ipReleaseMatch[2] === 'cancel') {
      if (!checkAdminMutationProtection(req, res, session)) return true;
      DB.exec('BEGIN IMMEDIATE');
      try {
        const row = DB.prepare(`SELECT id, ip_hash, remaining_uses FROM registration_ip_releases WHERE id = ? AND status = 'active' AND remaining_uses > 0`).get(releaseId);
        if (!row) { DB.exec('ROLLBACK'); sendError(res, 404, 'Liberação ativa não encontrada.'); return true; }
        const stamp = nowISO();
        DB.prepare(`UPDATE registration_ip_releases SET status = 'canceled', canceled_at = ?, canceled_by_admin_id = ?, updated_at = ? WHERE id = ? AND status = 'active'`)
          .run(stamp, session.admin.id, stamp, releaseId);
        writeAdminAudit(session, 'registration_ip_release_canceled', null, { releaseId, ipHash: row.ip_hash, remainingUsesRevoked: Number(row.remaining_uses) }, req);
        DB.exec('COMMIT');
      } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
      sendJson(res, 200, { canceled: true, message: 'Liberação do endereço IP cancelada com sucesso.' });
      return true;
    }
  }

  if (pathname === '/api/admin/deleted-accounts' && method === 'GET') {
    purgeExpiredDeletedAccounts();
    const rawPage = Number(url.searchParams.get('page') || 1);
    const rawSize = Number(url.searchParams.get('pageSize') || 20);
    if (!Number.isInteger(rawPage) || rawPage < 1 || !Number.isInteger(rawSize) || rawSize < 1 || rawSize > 100) { sendError(res, 400, 'Paginação inválida.'); return true; }
    const q = String(url.searchParams.get('q') || '').trim().slice(0, 120);
    const plan = url.searchParams.get('plan') || 'all';
    if (!['all', 'base', 'premium'].includes(plan)) { sendError(res, 400, 'Filtro de plano inválido.'); return true; }
    const where = ['expires_at > ?', 'recovered_at IS NULL']; const values = [nowISO()];
    if (plan !== 'all') { where.push('plan = ?'); values.push(plan); }
    if (q) { where.push('(full_name LIKE ? COLLATE NOCASE OR email LIKE ? COLLATE NOCASE)'); values.push(`%${q}%`, `%${q}%`); }
    const clause = where.join(' AND ');
    const total = Number(DB.prepare(`SELECT COUNT(*) AS n FROM deleted_accounts WHERE ${clause}`).get(...values).n);
    const pages = Math.max(1, Math.ceil(total / rawSize));
    const page = Math.min(rawPage, pages);
    const items = DB.prepare(`SELECT id, full_name, email, plan, account_created_at, deleted_at, deleted_by_admin_name
      FROM deleted_accounts WHERE ${clause} ORDER BY deleted_at DESC LIMIT ? OFFSET ?`).all(...values, rawSize, (page - 1) * rawSize)
      .map((row) => ({ id: row.id, fullName: row.full_name, email: row.email, plan: row.plan, createdAt: row.account_created_at, deletedAt: row.deleted_at, deletedBy: row.deleted_by_admin_name }));
    sendJson(res, 200, { items, page, pageSize: rawSize, total, pages, retentionDays: DELETION_ARCHIVE_RETENTION_DAYS });
    return true;
  }

  const deletedAccountMatch = pathname.match(/^\/api\/admin\/deleted-accounts\/([0-9a-f-]{36})$/i);
  if (deletedAccountMatch && method === 'GET') {
    purgeExpiredDeletedAccounts();
    const row = DB.prepare(`SELECT id, full_name, email, plan, plan_status, plan_started_at, plan_expires_at,
      premium_trial_started_at, premium_trial_ends_at, premium_first_billing_at, premium_first_billing_period_ends_at,
      premium_trial_consent_at, premium_trial_cancel_requested_at, premium_subscription_status,
      account_created_at, deleted_at, deleted_by_admin_name, reason, expires_at
      FROM deleted_accounts WHERE id = ? AND expires_at > ? AND recovered_at IS NULL`).get(deletedAccountMatch[1], nowISO());
    if (!row) { sendError(res, 404, 'Registro da Lixeira não encontrado ou expirado.'); return true; }
    writeAdminAudit(session, 'deleted_account_details_viewed', null, { deletionArchiveId: row.id }, req);
    sendJson(res, 200, { item: { id: row.id, fullName: row.full_name, email: row.email, plan: row.plan, planStatus: row.plan_status || null, planStartedAt: row.plan_started_at || null, planExpiresAt: row.plan_expires_at || null, createdAt: row.account_created_at, deletedAt: row.deleted_at, deletedBy: row.deleted_by_admin_name, reason: row.reason || null, expiresAt: row.expires_at, premiumTrialStartedAt: row.premium_trial_started_at || null, premiumTrialEndsAt: row.premium_trial_ends_at || null, premiumFirstBillingAt: row.premium_first_billing_at || null, premiumFirstBillingPeriodEndsAt: row.premium_first_billing_period_ends_at || null, premiumSubscriptionStatus: row.premium_subscription_status || 'none', passwordDisplay: 'Senha: protegida por segurança. Será necessário redefinir a senha para recuperar o acesso.' } });
    return true;
  }

  const deletedRestoreMatch = pathname.match(/^\/api\/admin\/deleted-accounts\/([0-9a-f-]{36})\/restore$/i);
  if (deletedRestoreMatch && method === 'POST') {
    if (!checkAdminMutationProtection(req, res, session)) return true;
    const archiveId = deletedRestoreMatch[1];
    DB.exec('BEGIN IMMEDIATE');
    try {
      const archive = DB.prepare(`SELECT * FROM deleted_accounts WHERE id=? AND expires_at>? AND recovered_at IS NULL`).get(archiveId, nowISO());
      if (!archive) { DB.exec('ROLLBACK'); sendError(res, 404, 'Registro pendente da Lixeira não encontrado ou expirado.'); return true; }
      const existing = DB.prepare('SELECT id FROM users WHERE email=? COLLATE NOCASE').get(archive.email)
        || DB.prepare('SELECT id FROM admin_users WHERE email=? COLLATE NOCASE').get(archive.email);
      if (existing) { DB.exec('ROLLBACK'); sendError(res, 409, 'Não foi possível recuperar: este e-mail já pertence a uma conta atual. Nenhuma conta foi alterada.', { code: 'DELETED_ACCOUNT_EMAIL_CONFLICT' }); return true; }
      const newUserId = crypto.randomUUID();
      const randomLockedPassword = crypto.randomBytes(48).toString('base64url');
      const password = await hashPassword(randomLockedPassword);
      const stamp = nowISO();
      let restoredPlan = archive.plan;
      let planStatus = archive.plan_status || (archive.plan === 'premium' ? 'legacy' : 'free');
      let planStartedAt = archive.plan_started_at || null;
      let planExpiresAt = archive.plan_expires_at || null;
      let subscriptionStatus = archive.premium_subscription_status || 'none';
      if (archive.plan === 'premium' && archive.premium_trial_ends_at) {
        if (archive.premium_trial_ends_at > stamp && ['trialing','cancel_scheduled'].includes(subscriptionStatus)) {
          restoredPlan = 'premium'; planStatus = 'demo'; planStartedAt = archive.premium_trial_started_at || archive.plan_started_at;
          planExpiresAt = archive.premium_trial_ends_at;
          if (subscriptionStatus === 'cancel_scheduled') subscriptionStatus = 'cancel_scheduled';
          else subscriptionStatus = 'trialing';
        } else {
          restoredPlan = 'base'; planStatus = 'expired'; planStartedAt = null; planExpiresAt = null;
          subscriptionStatus = subscriptionStatus === 'cancel_scheduled' ? 'canceled' : 'trial_expired';
        }
      }
      DB.prepare(`INSERT INTO users(id, full_name, email, password_salt, password_hash, plan, plan_status, plan_started_at, plan_expires_at,
        premium_trial_started_at, premium_trial_ends_at, premium_first_billing_at, premium_first_billing_period_ends_at,
        premium_trial_consent_at, premium_trial_cancel_requested_at, premium_subscription_status, account_status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`)
        .run(newUserId, archive.full_name, archive.email, password.salt, password.hash, restoredPlan, planStatus, planStartedAt, planExpiresAt,
          archive.premium_trial_started_at || null, archive.premium_trial_ends_at || null,
          archive.premium_first_billing_at || null, archive.premium_first_billing_period_ends_at || null,
          archive.premium_trial_consent_at || null, archive.premium_trial_cancel_requested_at || null, subscriptionStatus, stamp, stamp);
      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetExpires = new Date(Date.now() + 30 * 60_000).toISOString();
      DB.prepare(`INSERT INTO client_password_reset_tokens(id, user_id, token_hash, created_at, expires_at, issued_by_admin_id)
        VALUES (?, ?, ?, ?, ?, ?)`).run(crypto.randomUUID(), newUserId, hashToken(resetToken), stamp, resetExpires, session.admin.id);
      DB.prepare('UPDATE deleted_accounts SET recovered_at=?, recovered_user_id=? WHERE id=? AND recovered_at IS NULL').run(stamp, newUserId, archiveId);
      writeAdminAudit(session, 'deleted_account_restored', newUserId, { deletionArchiveId: archiveId, financialHistoryRestored: false, passwordResetRequired: true }, req);
      DB.exec('COMMIT');
      sendJson(res, 201, { restored: true, userId: newUserId, resetPath: `/reset-password?token=${encodeURIComponent(resetToken)}`, resetExpiresAt: resetExpires,
        plan: restoredPlan, message: 'Conta restaurada com um novo identificador. As sessões antigas continuam revogadas; gere a nova senha pelo link de uso único. Dados financeiros removidos na exclusão anterior não podem ser recuperados.' });
      return true;
    } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
  }

  if (pathname === '/api/admin/theme' && ['GET','PATCH','DELETE'].includes(method)) {
    const row = DB.prepare("SELECT theme_preferences FROM admin_users WHERE id=? AND role='admin' AND is_active=1").get(session.admin.id);
    if (!row) { sendError(res, 403, 'Acesso administrativo negado.'); return true; }
    let stored = {};
    try { const parsed = JSON.parse(row.theme_preferences || '{}'); if (isPlainObject(parsed)) stored = parsed; } catch {}
    if (method === 'GET') { sendJson(res, 200, { themes: stored }); return true; }
    if (!checkAdminMutationProtection(req, res, session)) return true;
    if (method === 'PATCH') {
      const body = await readJson(req);
      if (!isPlainObject(body) || !hasOnlyKeys(body, ['mode','accent','background','surface']) ||
          !['light','dark'].includes(body.mode) ||
          !['accent','background','surface'].every(k => typeof body[k] === 'string' && /^#[0-9a-fA-F]{6}$/.test(body[k]))) {
        sendError(res, 400, 'Informe três cores hexadecimais válidas e um tema.'); return true;
      }
      stored[body.mode] = { accent: body.accent.toUpperCase(), background: body.background.toUpperCase(), surface: body.surface.toUpperCase() };
      DB.prepare('UPDATE admin_users SET theme_preferences=?,updated_at=? WHERE id=?').run(JSON.stringify(stored),nowISO(),session.admin.id);
      writeAdminAudit(session,'admin_theme_saved',null,{ mode:body.mode, fields:['accent','background','surface'] },req);
    } else {
      const mode=url.searchParams.get('mode');
      if (!['light','dark'].includes(mode)) { sendError(res,400,'Selecione o tema que deseja restaurar.'); return true; }
      delete stored[mode];
      DB.prepare('UPDATE admin_users SET theme_preferences=?,updated_at=? WHERE id=?').run(JSON.stringify(stored),nowISO(),session.admin.id);
      writeAdminAudit(session,'admin_theme_reset',null,{mode},req);
    }
    sendJson(res,200,{themes:stored,message:method==='PATCH'?'Personalização administrativa salva.':'Cores do tema restauradas.'});
    return true;
  }
  if (pathname === '/api/admin/settings' && method === 'GET') {
    const row = DB.prepare('SELECT id, full_name, email, role, created_at FROM admin_users WHERE id = ? AND is_active = 1').get(session.admin.id);
    if (!row) { sendError(res, 401, 'Conta administrativa indisponível.'); return true; }
    sendJson(res, 200, { admin: { id: row.id, fullName: row.full_name, email: row.email, role: row.role, createdAt: row.created_at } });
    return true;
  }
  if (pathname === '/api/admin/settings' && method === 'PATCH') {
    if (!checkAdminMutationProtection(req, res, session)) return true;
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['fullName']) || !validateText(body.fullName, 120, true)) { sendError(res, 400, 'Informe um nome administrativo válido.'); return true; }
    const fullName = normalizeFullName(body.fullName);
    if (!isValidFullName(fullName) || fullName.length > 120) { sendError(res, 400, 'Informe um nome usando somente letras e espaços.'); return true; }
    DB.prepare('UPDATE admin_users SET full_name = ?, updated_at = ? WHERE id = ? AND is_active = 1').run(fullName, nowISO(), session.admin.id);
    writeAdminAudit(session, 'admin_name_updated', null, { changedFields: ['fullName'] }, req);
    sendJson(res, 200, { admin: { ...session.admin, fullName }, message: 'Nome administrativo atualizado.' });
    return true;
  }
  if (pathname === '/api/admin/account' && method === 'DELETE') {
    if (!checkAdminMutationProtection(req, res, session)) return true;
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['password']) || !validateText(body.password, 128, true)) { sendError(res, 400, 'Informe sua senha atual para confirmar.'); return true; }
    const row = DB.prepare("SELECT password_salt, password_hash FROM admin_users WHERE id = ? AND is_active = 1 AND role = 'admin'").get(session.admin.id);
    if (!row || !(await verifyAdminPassword(body.password, row.password_salt, row.password_hash))) { sendError(res, 403, 'Senha administrativa incorreta.'); return true; }
    DB.exec('BEGIN IMMEDIATE');
    try {
      writeAdminAudit(session, 'admin_account_deactivated', null, { method: 'self_deactivation' }, req);
      DB.prepare('UPDATE admin_users SET is_active = 0, updated_at = ? WHERE id = ?').run(nowISO(), session.admin.id);
      DB.prepare('DELETE FROM admin_sessions WHERE admin_user_id = ?').run(session.admin.id);
      DB.exec('COMMIT');
    } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
    sendJson(res, 200, { deactivated: true, message: 'Conta administrativa desativada e sessões encerradas.' }, { 'Set-Cookie': clearCookie('gc_admin_session') });
    return true;
  }

  if (pathname === '/api/admin/audit' && method === 'GET') {
    const limit = Math.min(100, Math.max(1, Number(url.searchParams.get('limit') || 50)));
    const rows = DB.prepare(`SELECT l.id, l.action, l.target_user_id, l.details_json, l.ip_address, l.created_at, a.full_name AS admin_name, u.full_name AS client_name, u.email AS client_email
      FROM admin_audit_logs l JOIN admin_users a ON a.id = l.admin_user_id LEFT JOIN users u ON u.id=l.target_user_id ORDER BY l.created_at DESC LIMIT ?`).all(limit)
      .map((row) => ({ id: row.id, action: row.action, target_user_id: row.target_user_id,
        admin_name: row.admin_name, created_at: row.created_at, clientName: row.client_name || null, clientEmail: row.client_email || null,
        ipAddress: normalizeIpAddress(row.ip_address) || 'Não disponível', details: safeParseJson(row.details_json) }));
    const securityRows = DB.prepare(`SELECT e.id,e.event_type,e.details_json,e.created_at,e.source_ip_hash,e.source_ip_address,u.full_name,u.email
      FROM user_security_events e LEFT JOIN users u ON u.id=e.user_id
      WHERE e.event_type IN ('client_login_short_locked','client_login_account_locked','client_login_unlocked')
      ORDER BY e.created_at DESC LIMIT ?`).all(limit).map((row) => {
        let details = {}; try { details = JSON.parse(row.details_json || '{}'); } catch {}
        return { id: row.id, action: row.event_type, target_user_id: null, admin_name: row.event_type === 'client_login_unlocked' ? (details.adminName || 'Operação administrativa') : 'Sistema',
          created_at: row.created_at, ipAddress: normalizeIpAddress(row.source_ip_address) || 'Não disponível', clientName: row.full_name || 'Conta removida', clientEmail: row.email || null,
          reason: details.reason || null, lockedUntil: details.lockedUntil || null };
      });
    sendJson(res, 200, { items: [...rows, ...securityRows].sort((a,b) => String(b.created_at).localeCompare(String(a.created_at))).slice(0, limit) });
    return true;
  }

  const resetClientMatch = pathname.match(/^\/api\/admin\/clients\/([0-9a-f-]{36})\/password-reset$/i);
  if (resetClientMatch && method === 'POST') {
    if (!checkAdminMutationProtection(req, res, session)) return true;
    const clientId = resetClientMatch[1];
    const client = DB.prepare('SELECT id, full_name, account_status FROM users WHERE id = ?').get(clientId);
    if (!client || client.account_status !== 'active') { sendError(res, 404, 'Cliente ativo não encontrado.'); return true; }
    const token = crypto.randomBytes(32).toString('hex');
    const stamp = nowISO();
    const expires = new Date(Date.now() + 30 * 60_000).toISOString();
    DB.exec('BEGIN IMMEDIATE');
    try {
      DB.prepare('DELETE FROM client_password_reset_tokens WHERE user_id = ? AND used_at IS NULL').run(clientId);
      DB.prepare(`INSERT INTO client_password_reset_tokens(id, user_id, token_hash, created_at, expires_at, issued_by_admin_id)
        VALUES (?, ?, ?, ?, ?, ?)`).run(crypto.randomUUID(), clientId, hashToken(token), stamp, expires, session.admin.id);
      writeAdminAudit(session, 'client_password_reset_link_generated', clientId, { expiresAt: expires, delivery: 'manual_link' }, req);
      DB.exec('COMMIT');
    } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
    sendJson(res, 201, { resetPath: `/reset-password?token=${encodeURIComponent(token)}`, expiresAt: expires, message: 'Link de redefinição gerado. Ele é de uso único e expira em 30 minutos.' });
    return true;
  }

  const clientId = parseAdminClientId(pathname);
  if (clientId) {
    if (method === 'GET') {
      const row = DB.prepare('SELECT * FROM users WHERE id = ?').get(clientId);
      if (!row) { sendError(res, 404, 'Cliente não encontrado.'); return true; }
      const expenses = Number(DB.prepare('SELECT COUNT(*) AS n FROM expenses WHERE user_id = ?').get(clientId).n);
      const calculations = Number(DB.prepare('SELECT COUNT(*) AS n FROM installment_calculations WHERE user_id = ?').get(clientId).n);
      const recurrences = Number(DB.prepare('SELECT COUNT(*) AS n FROM recurrence_rules WHERE user_id = ?').get(clientId).n);
      const linked = Number(DB.prepare('SELECT COUNT(*) AS n FROM account_link_members WHERE user_id = ? OR group_id IN (SELECT group_id FROM account_link_members WHERE user_id = ?)').get(clientId, clientId).n);
      const lastActivity = DB.prepare('SELECT MAX(last_seen_at) AS last_seen FROM sessions WHERE user_id = ?').get(clientId).last_seen;
      const paymentCount = Number(DB.prepare('SELECT COUNT(*) AS n FROM payment_records WHERE user_id = ?').get(clientId).n);
      const planHistory = DB.prepare(`SELECT action, created_at, details_json FROM admin_audit_logs
        WHERE target_user_id = ? AND action = 'client_plan_changed' ORDER BY created_at DESC LIMIT 20`).all(clientId)
        .map((item) => ({ action: item.action, date: item.created_at, details: safeParseJson(item.details_json) }));
      writeAdminAudit(session, 'client_sensitive_details_viewed', clientId, { fields: ['income', 'budget', 'activity', 'counts'] }, req);
      sendJson(res, 200, {
        client: adminPublicClient(row), createdAt: row.created_at, updatedAt: row.updated_at,
        firstAccessAt: row.first_login_at || null, lastAccessAt: row.last_login_at || null, lastAccessIp: row.last_login_ip || 'Não disponível',
        monthlyIncomeCents: row.monthly_income_cents, monthlyBudgetCents: row.monthly_budget_cents,
        expenseCount: expenses, calculationCount: calculations, recurrenceCount: recurrences,
        linkedAccountCount: linked, lastActivity: lastActivity || null,
        passwordDisplay: 'Protegida por hash — não visualizável.',
        paymentMethodDisplay: 'Nenhuma forma de pagamento cadastrada.', paymentCount,
        personalData: { cpf: null, phone: null, address: null },
        subscription: { plan: row.plan, valueCents: null,
          startedAt: row.plan_started_at || null, expiresAt: row.plan_expires_at || null,
          status: paymentStatusForUser(row), paymentRecords: paymentCount },
        planHistory
      });
      return true;
    }
    if (method === 'PATCH') {
      if (!checkAdminMutationProtection(req, res, session)) return true;
      const body = await readJson(req);
      const allowed = ['fullName', 'email', 'plan', 'accountStatus'];
      if (!isPlainObject(body) || !Object.keys(body).length || !hasOnlyKeys(body, allowed)) { sendError(res, 400, 'Os campos enviados para edição não são permitidos.'); return true; }
      const row = DB.prepare('SELECT * FROM users WHERE id = ?').get(clientId);
      if (!row) { sendError(res, 404, 'Cliente não encontrado.'); return true; }
      const nextName = body.fullName === undefined ? row.full_name : normalizeFullName(body.fullName);
      const nextEmail = body.email === undefined ? row.email : normalizeEmail(body.email);
      const nextPlan = body.plan === undefined ? row.plan : body.plan;
      const nextStatus = body.accountStatus === undefined ? (row.account_status || 'active') : body.accountStatus;
      if (body.fullName !== undefined && (!isValidFullName(nextName) || nextName.length > 120)) { sendError(res, 400, 'Informe um nome válido.'); return true; }
      if (body.email !== undefined && (!isValidEmailAddress(nextEmail) || nextEmail.length > 254)) { sendError(res, 400, 'Informe um e-mail válido.'); return true; }
      if (!['base', 'premium'].includes(nextPlan) || !['active', 'deactivated'].includes(nextStatus)) { sendError(res, 400, 'Plano ou situação da conta inválidos.'); return true; }
      if (DB.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE AND id <> ?').get(nextEmail, clientId) || DB.prepare('SELECT id FROM admin_users WHERE email = ? COLLATE NOCASE').get(nextEmail)) {
        sendError(res, 409, 'Este e-mail já está sendo utilizado.'); return true;
      }
      const planChanged = nextPlan !== row.plan;
      if (planChanged && nextPlan === 'premium' && !LOCAL_PREMIUM_ACCESS) { sendError(res, 409, 'O plano Premium depende de contratação e autorização confirmadas pelo provedor.'); return true; }
      const activeProviderSubscription = DB.prepare("SELECT id,provider_subscription_id FROM payment_subscriptions WHERE user_id=? AND status IN ('creating','pending','authorized','trialing','active','past_due') AND provider_subscription_id IS NOT NULL ORDER BY created_at DESC LIMIT 1").get(clientId);
      const mustCancelSubscription = Boolean(activeProviderSubscription?.provider_subscription_id && (nextStatus === 'deactivated' || (planChanged && nextPlan === 'base')));
      if (mustCancelSubscription) {
        try { const canceled = await MercadoPago.cancelSubscription(activeProviderSubscription.provider_subscription_id); if (canceled?.status && !['canceled','cancelled'].includes(String(canceled.status))) throw new Error('Não confirmado'); }
        catch { sendError(res, 502, 'Não foi possível confirmar o cancelamento da assinatura no provedor. O cadastro não foi alterado.'); return true; }
      }
      const stamp = nowISO();
      let planStatus = row.plan_status || (row.plan === 'premium' ? 'legacy' : 'free');
      let planStartedAt = row.plan_started_at || null;
      let planExpiresAt = row.plan_expires_at || null;
      if (planChanged && nextPlan === 'base') { planStatus = 'free'; planStartedAt = null; planExpiresAt = null; }
      if (planChanged && nextPlan === 'premium') { planStatus = 'legacy'; planStartedAt = stamp; planExpiresAt = null; }
      const nextPremiumStatus = mustCancelSubscription ? 'canceled'
        : planChanged ? (nextPlan === 'premium' && LOCAL_PREMIUM_ACCESS ? 'local_access' : 'none')
          : (row.premium_subscription_status || 'none');
      const clearProviderReferences = mustCancelSubscription || planChanged;
      DB.exec('BEGIN IMMEDIATE');
      try {
        DB.prepare(`UPDATE users SET full_name = ?, email = ?, plan = ?, plan_status = ?, plan_started_at = ?, plan_expires_at = ?,
          account_status = ?, premium_subscription_status=?,
          premium_provider_subscription_id=CASE WHEN ? THEN NULL ELSE premium_provider_subscription_id END,
          premium_next_payment_at=CASE WHEN ? THEN NULL ELSE premium_next_payment_at END, updated_at = ? WHERE id = ?`)
          .run(nextName, nextEmail, nextPlan, planStatus, planStartedAt, planExpiresAt, nextStatus, nextPremiumStatus,
            clearProviderReferences ? 1 : 0, clearProviderReferences ? 1 : 0, stamp, clientId);
        const accountDataChanged = nextName !== row.full_name || nextEmail.toLowerCase() !== row.email.toLowerCase() || nextPlan !== row.plan || nextStatus !== row.account_status;
        if (accountDataChanged && nextStatus === 'active') {
          DB.prepare('INSERT INTO account_notifications(id,user_id,kind,message,created_at) VALUES(?,?,?,?,?)')
            .run(crypto.randomUUID(), clientId, 'profile_updated', 'Seus dados foram atualizados por um administrador.', stamp);
        }
        if (mustCancelSubscription) DB.prepare(`UPDATE payment_subscriptions SET status='canceled', provider_status='canceled', canceled_at=COALESCE(canceled_at,?), updated_at=? WHERE id=?`).run(stamp, stamp, activeProviderSubscription.id);
        let detachedGroups = null;
        if (nextStatus === 'deactivated') {
          DB.prepare('DELETE FROM sessions WHERE user_id = ?').run(clientId);
          detachedGroups = detachAccountGroupsForDeactivation(clientId);
        }
        const auditDetails = { changedFields: Object.keys(body), planChanged, previousPlan: row.plan, nextPlan, accountStatus: nextStatus, detachedGroups };
        if (planChanged) writeAdminAudit(session, 'client_plan_changed', clientId, auditDetails, req);
        if (nextStatus !== row.account_status) {
          writeAdminAudit(session, nextStatus === 'deactivated' ? 'client_deactivated' : 'client_reactivated', clientId, auditDetails, req);
        }
        if (!planChanged && nextStatus === row.account_status) writeAdminAudit(session, 'client_updated', clientId, auditDetails, req);
        DB.exec('COMMIT');
      } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
      const fresh = DB.prepare('SELECT * FROM users WHERE id = ?').get(clientId);
      sendJson(res, 200, { client: adminPublicClient(fresh), message: 'Cadastro atualizado com sucesso.' });
      return true;
    }
    if (method === 'DELETE') {
      if (!checkAdminMutationProtection(req, res, session)) return true;
      const body = await readJson(req);
      if (!isPlainObject(body) || !hasOnlyKeys(body, ['reason']) || (body.reason !== undefined && !validateText(body.reason, 500, false))) {
        sendError(res, 400, 'O motivo da exclusão é inválido.'); return true;
      }
      const row = DB.prepare(`SELECT id, full_name, email, plan, plan_status, plan_started_at, plan_expires_at,
        premium_trial_started_at, premium_trial_ends_at, premium_first_billing_at, premium_first_billing_period_ends_at,
        premium_trial_consent_at, premium_trial_cancel_requested_at, premium_subscription_status, created_at
        FROM users WHERE id = ?`).get(clientId);
      if (!row) { sendError(res, 404, 'Cliente não encontrado.'); return true; }
      const stamp = nowISO();
      const archiveId = crypto.randomUUID();
      const expiresAt = new Date(Date.now() + DELETION_ARCHIVE_RETENTION_DAYS * 86400000).toISOString();
      const reason = String(body.reason || '').trim().slice(0, 500) || null;
      DB.exec('BEGIN IMMEDIATE');
      try {
        // Cria um registro administrativo separado; ele não participa da tabela
        // users nem de suas restrições únicas, então o e-mail pode ser reutilizado.
        DB.prepare(`INSERT INTO deleted_accounts
          (id, original_user_id, full_name, email, plan, plan_status, plan_started_at, plan_expires_at,
           premium_trial_started_at, premium_trial_ends_at, premium_first_billing_at, premium_first_billing_period_ends_at,
           premium_trial_consent_at, premium_trial_cancel_requested_at, premium_subscription_status,
           account_created_at, deleted_at, deleted_by_admin_id, deleted_by_admin_name, reason, expires_at, metadata_json)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}')`)
          .run(archiveId, row.id, row.full_name, row.email, row.plan, row.plan_status || null, row.plan_started_at || null,
            row.plan_expires_at || null, row.premium_trial_started_at || null, row.premium_trial_ends_at || null,
            row.premium_first_billing_at || null, row.premium_first_billing_period_ends_at || null, row.premium_trial_consent_at || null,
            row.premium_trial_cancel_requested_at || null, row.premium_subscription_status || 'none', row.created_at, stamp,
            session.admin.id, session.admin.fullName, reason, expiresAt);
        const activeSessions = DB.prepare('SELECT token_hash FROM sessions WHERE user_id=?').all(clientId);
        const revokedUntil = new Date(Date.now() + 7 * 86400000).toISOString();
        const revokedInsert = DB.prepare('INSERT OR REPLACE INTO revoked_account_sessions(token_hash,expires_at) VALUES(?,?)');
        for (const activeSession of activeSessions) revokedInsert.run(activeSession.token_hash, revokedUntil);
        const deletedEmailHash = crypto.createHmac('sha256', REGISTRATION_IP_HMAC_KEY).update('deleted-account-notice-v1:').update(normalizeEmail(row.email)).digest('hex');
        DB.prepare('INSERT OR REPLACE INTO deleted_account_notices(email_hash,deleted_at,expires_at) VALUES(?,?,?)')
          .run(deletedEmailHash, stamp, new Date(Date.now() + 30 * 86400000).toISOString());
        DB.prepare('DELETE FROM sessions WHERE user_id = ?').run(clientId);
        DB.prepare('DELETE FROM client_password_reset_tokens WHERE user_id = ?').run(clientId);
        DB.prepare('DELETE FROM pending_registrations WHERE email = ? COLLATE NOCASE').run(row.email);
        DB.prepare(`UPDATE payment_records SET user_id = NULL, provider = 'anonymized',
          provider_payment_id = 'anonymized-' || id, updated_at = ? WHERE user_id = ?`).run(stamp, clientId);
        DB.prepare('DELETE FROM user_access_logs WHERE user_id = ?').run(clientId);
        DB.prepare('DELETE FROM admin_audit_logs WHERE target_user_id = ?').run(clientId);
        DB.prepare('DELETE FROM users WHERE id = ?').run(clientId);
        writeAdminAudit(session, 'client_permanently_deleted_anonymized', null, { deletionArchiveId: archiveId, archiveRetentionDays: DELETION_ARCHIVE_RETENTION_DAYS }, req);
        DB.exec('COMMIT');
      } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
      sendJson(res, 200, { deleted: true, deletionArchiveId: archiveId, message: `Cliente excluído definitivamente. Um registro administrativo mínimo foi guardado na Lixeira por até ${DELETION_ARCHIVE_RETENTION_DAYS} dias; os dados de autenticação, sessões e dados financeiros pessoais foram removidos ou desvinculados.` });
      return true;
    }
  }

  sendError(res, 404, 'Endpoint administrativo não encontrado.');
  return true;
}
function safeParseJson(value) { try { return JSON.parse(value); } catch { return {}; } }
function adminLoginAttemptKey(email, req) {
  return crypto.createHash('sha256').update(`${email}|${requestIp(req)}`).digest('hex');
}
function adminLoginIsLocked(email, req) {
  const key = adminLoginAttemptKey(email, req);
  const row = DB.prepare('SELECT locked_until FROM admin_login_attempts WHERE bucket_key = ?').get(key);
  return Boolean(row?.locked_until && row.locked_until > nowISO());
}
function registerAdminLoginFailure(email, req) {
  const key = adminLoginAttemptKey(email, req);
  const stamp = nowISO();
  DB.exec('BEGIN IMMEDIATE');
  try {
    const row = DB.prepare('SELECT window_started_at, failed_attempts, locked_until FROM admin_login_attempts WHERE bucket_key = ?').get(key);
    let failed = row && Date.now() - Date.parse(row.window_started_at) < 15 * 60_000 ? Number(row.failed_attempts) + 1 : 1;
    const windowStarted = row && Date.now() - Date.parse(row.window_started_at) < 15 * 60_000 ? row.window_started_at : stamp;
    const lockedUntil = failed >= 8 ? new Date(Date.now() + 15 * 60_000).toISOString() : null;
    DB.prepare(`INSERT INTO admin_login_attempts(bucket_key, window_started_at, failed_attempts, locked_until) VALUES (?, ?, ?, ?)
      ON CONFLICT(bucket_key) DO UPDATE SET window_started_at=excluded.window_started_at, failed_attempts=excluded.failed_attempts, locked_until=excluded.locked_until`)
      .run(key, windowStarted, failed, lockedUntil);
    DB.exec('COMMIT');
    return { locked: Boolean(lockedUntil), remaining: Math.max(0, 8 - failed) };
  } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
}
function clearAdminLoginFailures(email, req) {
  DB.prepare('DELETE FROM admin_login_attempts WHERE bucket_key = ?').run(adminLoginAttemptKey(email, req));
}

function ensureAccountLinkGroup(userId) {
  const owner = DB.prepare('SELECT id, plan FROM users WHERE id = ?').get(userId);
  if (!owner || Plans.planFor(owner.plan) !== 'premium') return null;

  // A consulta do seletor não cria grupos. A criação e o reparo de vínculos
  // acontecem somente no fluxo de inclusão, sob transação exclusiva.
  DB.exec('BEGIN IMMEDIATE');
  try {
    const raced = DB.prepare('SELECT group_id FROM account_link_members WHERE user_id = ?').get(userId);
    if (raced) {
      const validGroup = DB.prepare('SELECT id FROM account_link_groups WHERE id = ?').get(raced.group_id);
      if (validGroup) { DB.exec('COMMIT'); return raced.group_id; }
      // A associação aponta para um grupo inexistente. Ela é um registro órfão,
      // não uma vinculação ativa; removemos apenas essa linha e reconstruímos
      // a associação pessoal do proprietário sem afetar outros usuários.
      DB.prepare('DELETE FROM account_link_members WHERE user_id = ? AND group_id = ?').run(userId, raced.group_id);
    }

    const ownedGroup = DB.prepare('SELECT id FROM account_link_groups WHERE owner_user_id = ?').get(userId);
    if (ownedGroup) {
      const members = DB.prepare('SELECT user_id FROM account_link_members WHERE group_id = ?').all(ownedGroup.id);
      if (members.some((member) => member.user_id === userId)) {
        DB.exec('COMMIT');
        return ownedGroup.id;
      }
      // Não removemos membros para consertar um grupo legado que já tenha
      // ocupado as três vagas sem o proprietário. Nesse caso, falhamos fechados.
      if (members.length >= 3) {
        DB.exec('COMMIT');
        return null;
      }
      DB.prepare('INSERT INTO account_link_members(group_id, user_id, linked_at) VALUES (?, ?, ?)')
        .run(ownedGroup.id, userId, nowISO());
      DB.exec('COMMIT');
      return ownedGroup.id;
    }

    const groupId = crypto.randomUUID();
    DB.prepare('INSERT INTO account_link_groups(id, owner_user_id, created_at) VALUES (?, ?, ?)').run(groupId, userId, nowISO());
    DB.prepare('INSERT INTO account_link_members(group_id, user_id, linked_at) VALUES (?, ?, ?)').run(groupId, userId, nowISO());
    DB.exec('COMMIT');
    return groupId;
  } catch (error) {
    try { DB.exec('ROLLBACK'); } catch { /* a transaction may already have completed */ }
    const raced = DB.prepare('SELECT group_id FROM account_link_members WHERE user_id = ?').get(userId);
    if (raced && DB.prepare('SELECT id FROM account_link_groups WHERE id = ?').get(raced.group_id)) return raced.group_id;
    throw error;
  }
}
function linkedAccountsFor(userRow) {
  // Importante: GET /api/accounts/linked é somente leitura. A versão anterior criava
  // um grupo Premium singleton ao abrir o seletor, fazendo uma conta recém-criada
  // parecer vinculada a outro grupo quando era adicionada por um segundo usuário.
  const member = DB.prepare('SELECT group_id FROM account_link_members WHERE user_id = ?').get(userRow.id);
  if (!member) {
    const plan = Plans.planFor(userRow.plan);
    return {
      accounts: [{ ...safePublicUser(userRow), current: true }],
      canAdd: plan === 'premium', canSwitch: false, maxAccounts: plan === 'premium' ? Plans.LINKED_ACCOUNTS_PREMIUM : 1,
      linkedCount: 1, reason: plan === 'premium' ? null : 'base_single_account',
      ownerPlan: plan, groupId: null
    };
  }
  const group = DB.prepare(`SELECT g.id AS group_id, g.owner_user_id, owner.plan AS owner_plan
    FROM account_link_groups g JOIN users owner ON owner.id = g.owner_user_id WHERE g.id = ?`).get(member.group_id);
  if (!group) {
    const plan = Plans.planFor(userRow.plan);
    // Um vínculo órfão não é apresentado como um grupo válido. Para Premium,
    // a interface mantém a opção de inclusão, que fará o reparo atômico no POST.
    return { accounts: [{ ...safePublicUser(userRow), current: true }], canAdd: plan === 'premium', canSwitch: false, maxAccounts: plan === 'premium' ? Plans.LINKED_ACCOUNTS_PREMIUM : 1, linkedCount: 1, reason: plan === 'premium' ? null : 'base_single_account', ownerPlan: plan, groupId: null, repairableOrphan: true };
  }
  const members = DB.prepare(`SELECT u.* FROM account_link_members m JOIN users u ON u.id = m.user_id
    WHERE m.group_id = ? ORDER BY CASE WHEN u.id = ? THEN 0 ELSE 1 END, m.linked_at ASC`).all(member.group_id, userRow.id);
  const count = members.length;
  const canAdd = Plans.planFor(group.owner_plan) === 'premium' && count < Plans.LINKED_ACCOUNTS_PREMIUM;
  return {
    accounts: members.map((user) => ({ ...safePublicUser(user), current: user.id === userRow.id })),
    canAdd, canSwitch: Plans.planFor(group.owner_plan) === 'premium' && count > 1, maxAccounts: Plans.LINKED_ACCOUNTS_PREMIUM, linkedCount: count,
    reason: Plans.planFor(group.owner_plan) !== 'premium' ? 'owner_not_premium' : count >= Plans.LINKED_ACCOUNTS_PREMIUM ? 'account_limit_reached' : null,
    ownerPlan: Plans.planFor(group.owner_plan), groupId: group.group_id
  };
}
async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = await scryptAsync(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return { salt: salt.toString('hex'), hash: derived.toString('hex') };
}
async function verifyPassword(password, saltHex, hashHex) {
  try {
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(hashHex, 'hex');
    if (!salt.length || expected.length !== 64) return false;
    const actual = await scryptAsync(password, salt, expected.length, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
    return crypto.timingSafeEqual(actual, expected);
  } catch { return false; }
}
function validateNewUser(body) {
  if (!isPlainObject(body) || !hasOnlyKeys(body, ['fullName', 'email', 'password', 'confirmPassword', 'plan'])) return 'A solicitação contém campos não permitidos.';
  if (body.plan !== undefined && !['base', 'premium'].includes(body.plan)) return 'Selecione um plano válido.';
  if (!validateText(body.fullName, 200, true) || !isValidFullName(body.fullName)) return 'Informe um nome usando somente letras e espaços.';
  if (!validateText(body.email, 254, true) || !isValidEmailAddress(body.email)) return 'Digite um endereço de e-mail válido e confira o domínio.';
  if (!isValidNewPassword(body.password)) return 'A senha precisa conter um número, um caractere especial e uma letra maiúscula.';
  if (body.password !== body.confirmPassword) return 'A confirmação de senha não corresponde.';
  return null;
}
function validateExpense(body, partial = false) {
  const allowed = ['description', 'amount', 'category', 'expenseDate', 'dueDate', 'status', 'paymentMethod', 'notes', 'recurrence'];
  if (!isPlainObject(body) || !hasOnlyKeys(body, allowed)) return 'A despesa contém campos inválidos.';
  if (partial && Object.keys(body).length === 0) return 'Informe ao menos um campo para alterar.';
  if (partial && Object.hasOwn(body, 'recurrence')) return 'A recorrência é gerenciada separadamente; este formulário altera apenas a despesa.';
  if (!partial && ['description', 'amount', 'category', 'expenseDate', 'status', 'paymentMethod', 'recurrence'].some((key) => body[key] === undefined)) return 'Preencha descrição, valor, categoria, data, situação, forma de pagamento e recorrência.';
  if (body.description !== undefined && (!validateText(body.description, 120, true) || !body.description.trim())) return 'A descrição precisa ter até 120 caracteres.';
  if (body.amount !== undefined) {
    const cents = Finance.parseMoneyCents(body.amount);
    if (!Number.isSafeInteger(cents) || cents < 0 || cents > 9_000_000_000_000) return 'Informe um valor válido em reais.';
  }
  if (body.category !== undefined && !CATEGORY_IDS.has(body.category)) return 'Selecione uma categoria válida.';
  if (body.expenseDate !== undefined && !isAllowedExpenseDate(body.expenseDate)) return 'A data não pode ser anterior a 1950.';
  if (body.dueDate !== undefined && !isAllowedExpenseDate(body.dueDate, true)) return 'A data não pode ser anterior a 1950.';
  if (body.status !== undefined && !STATUSES.has(body.status)) return 'A situação deve ser paga ou pendente.';
  if (body.paymentMethod !== undefined && !PAYMENT_METHODS.has(body.paymentMethod)) return 'Selecione uma forma de pagamento válida.';
  if (body.notes !== undefined && !validateText(body.notes, 1000)) return 'As observações devem ter no máximo 1.000 caracteres.';
  if (body.recurrence !== undefined && !RECURRENCES.has(body.recurrence)) return 'Selecione uma recorrência válida.';
  return null;
}
function expenseRow(row) {
  return {
    id: row.id, description: row.description, amountCents: row.amount_cents, category: row.category,
    expenseDate: row.expense_date, dueDate: row.due_date, status: row.status,
    paymentMethod: row.payment_method, notes: row.notes, recurrenceRuleId: row.recurrence_rule_id,
    occurrenceDate: row.occurrence_date, completedAt: row.completed_at || null, createdAt: row.created_at, updatedAt: row.updated_at
  };
}
function calculationRow(row) {
  return {
    id: row.id, description: row.item_description, priceCents: row.price_cents,
    downPaymentCents: row.down_payment_cents, feeCents: row.fee_cents,
    count: row.installment_count, monthlyInterestBps: row.monthly_interest_bps,
    financedCents: row.financed_cents, installmentCents: row.installment_cents,
    installmentsTotalCents: row.installments_total_cents, totalPaidCents: row.total_paid_cents,
    interestAndFeesCents: row.interest_and_fees_cents, monthlyBudgetCents: row.monthly_budget_cents,
    createdAt: row.created_at
  };
}

function bankAccountRow(row) {
  return { id: row.id, institution: row.institution, accountLabel: row.account_label, createdAt: row.created_at, updatedAt: row.updated_at };
}
function incomeRecordRow(row) {
  return {
    id: row.id, amountCents: row.amount_cents, receivedDate: row.received_date,
    bankAccountId: row.bank_account_id, bankInstitution: row.bank_institution || null,
    accountLabel: row.account_label || null, source: row.source, payerName: row.payer_name,
    description: row.description, createdAt: row.created_at, updatedAt: row.updated_at
  };
}
function requirePremiumFeature(session, res, feature = 'A área Recebidos') {
  if (Plans.planFor(session.user.plan) === 'premium') return true;
  sendError(res, 403, `${feature} é um benefício exclusivo do plano Premium.`, { code: 'PREMIUM_REQUIRED', upgrade: true });
  return false;
}
function validateIncomePayload(body, partial = false) {
  const allowed = ['amount', 'receivedDate', 'bankAccountId', 'source', 'payerName', 'description'];
  if (!isPlainObject(body) || !hasOnlyKeys(body, allowed) || (partial && Object.keys(body).length === 0)) return 'O recebimento contém campos inválidos.';
  if (!partial && allowed.slice(0, 5).some((key) => body[key] === undefined)) return 'Preencha valor, data, conta de destino, origem e responsável pelo pagamento.';
  if (body.amount !== undefined) {
    const cents = Finance.parseMoneyCents(body.amount);
    if (!Number.isSafeInteger(cents) || cents <= 0 || cents > 9_000_000_000_000) return 'Informe um valor recebido maior que zero.';
  }
  if (body.receivedDate !== undefined && (!isAllowedExpenseDate(body.receivedDate) || body.receivedDate > todayLocal())) return 'Informe uma data entre 01/01/1950 e hoje.';
  if (body.bankAccountId !== undefined && (typeof body.bankAccountId !== 'string' || !/^[0-9a-f-]{36}$/i.test(body.bankAccountId))) return 'Selecione uma conta bancária válida.';
  if (body.source !== undefined && (!validateText(body.source, 80, true) || !body.source.trim())) return 'Informe a origem do recebimento.';
  if (body.payerName !== undefined && (!validateText(body.payerName, 120, true) || !body.payerName.trim())) return 'Informe o nome de quem realizou o pagamento.';
  if (body.description !== undefined && !validateText(body.description, 1000)) return 'A descrição deve ter até 1.000 caracteres.';
  return null;
}
function validBankPayload(body, partial = false) {
  const allowed = ['institution', 'accountLabel'];
  if (!isPlainObject(body) || !hasOnlyKeys(body, allowed) || (partial && Object.keys(body).length === 0)) return 'Os dados da conta bancária são inválidos.';
  if (!partial && allowed.some((key) => body[key] === undefined)) return 'Informe a instituição financeira e uma identificação para a conta.';
  if (body.institution !== undefined && (!validateText(body.institution, 100, true) || !body.institution.trim())) return 'Informe uma instituição financeira válida.';
  if (body.accountLabel !== undefined && (!validateText(body.accountLabel, 80, true) || !body.accountLabel.trim())) return 'Informe uma identificação para a conta.';
  return null;
}
function parseHistoryRange(params) {
  const month = params.get('month');
  if (month) {
    try { return { ...Finance.monthRange(month), month }; }
    catch { return { error: 'Mês inválido. Use AAAA-MM.' }; }
  }
  const from = params.get('from') || '1950-01-01';
  const to = params.get('to') || todayLocal();
  if (!Finance.isISODate(from) || !Finance.isISODate(to) || from < '1950-01-01' || to < from || to > todayLocal()) return { error: 'Informe um intervalo de datas válido.' };
  return { start: from, end: to, month: null };
}
function parseDashboardRange(params, plan) {
  const today = todayLocal();
  const current = currentMonth();
  const currentRange = Finance.monthRange(current);
  const period = params.get('period') || 'thisMonth';
  let start = currentRange.start, end = currentRange.end;
  if (period === 'lastMonth') {
    const previous = Plans.addMonths(current, -1); const range = Finance.monthRange(previous); start = range.start; end = range.end;
  } else if (period === 'last30') start = new Date(Date.parse(`${today}T00:00:00Z`) - 29 * 86400000).toISOString().slice(0, 10);
  else if (period === 'last90') start = new Date(Date.parse(`${today}T00:00:00Z`) - 89 * 86400000).toISOString().slice(0, 10);
  else if (period === 'thisYear') start = `${today.slice(0, 4)}-01-01`;
  else if (period === 'all') start = '1950-01-01';
  else if (period === 'custom') {
    start = params.get('from') || '';
    end = params.get('to') || '';
    if (!Finance.isISODate(start) || !Finance.isISODate(end) || start < '1950-01-01' || end < start || end > today) return { error: 'Selecione um intervalo personalizado válido.' };
  } else if (period !== 'thisMonth') return { error: 'Período inválido.' };
  return { start, end, period };
}

function exportUsage(userId) {
  const usedRows = DB.prepare(`SELECT module, format, COUNT(*) AS used FROM export_downloads
    WHERE user_id = ? AND status = 'completed' AND substr(created_at,1,7) = ? GROUP BY module, format`).all(userId, currentMonth());
  const accountRows = DB.prepare(`SELECT format, COUNT(*) AS used FROM account_export_downloads
    WHERE user_id = ? AND status = 'completed' AND substr(created_at,1,7) = ? GROUP BY format`).all(userId, currentMonth());
  const out = { history: {}, expenses: {}, account: {} };
  for (const module of ['history', 'expenses']) for (const format of ['pdf', 'xlsx']) {
    const row = usedRows.find((item) => item.module === module && item.format === format);
    const used = Number(row?.used || 0);
    out[module][format] = { used, limit: Plans.BASE_EXPORT_LIMIT, remaining: Math.max(0, Plans.BASE_EXPORT_LIMIT - used) };
  }
  for (const format of ['pdf', 'xlsx']) {
    const row = accountRows.find((item) => item.format === format);
    const used = Number(row?.used || 0);
    out.account[format] = { used, limit: Plans.BASE_EXPORT_LIMIT, remaining: Math.max(0, Plans.BASE_EXPORT_LIMIT - used) };
  }
  return out;
}
function reserveExportDownload(userId, plan, module, format) {
  const isPremium = Plans.planFor(plan) === 'premium';
  const isAccount = module === 'account';
  if (!['history', 'expenses', 'account'].includes(module) || !['pdf', 'xlsx'].includes(format)) return { allowed: false, used: Plans.BASE_EXPORT_LIMIT, limit: Plans.BASE_EXPORT_LIMIT };
  const table = isAccount ? 'account_export_downloads' : 'export_downloads';
  DB.exec('BEGIN IMMEDIATE');
  try {
    const stale = new Date(Date.now() - 15 * 60_000).toISOString();
    DB.prepare(`DELETE FROM ${table} WHERE status = 'reserved' AND created_at < ?`).run(stale);
    const count = isAccount
      ? Number(DB.prepare(`SELECT COUNT(*) AS total FROM account_export_downloads WHERE user_id = ? AND format = ? AND substr(created_at,1,7) = ? AND (status = 'completed' OR (status = 'reserved' AND created_at >= ?))`).get(userId, format, currentMonth(), stale).total)
      : Number(DB.prepare(`SELECT COUNT(*) AS total FROM export_downloads WHERE user_id = ? AND module = ? AND format = ? AND substr(created_at,1,7) = ? AND (status = 'completed' OR (status = 'reserved' AND created_at >= ?))`).get(userId, module, format, currentMonth(), stale).total);
    if (!isPremium && count >= Plans.BASE_EXPORT_LIMIT) {
      DB.exec('COMMIT');
      return { allowed: false, used: count, limit: Plans.BASE_EXPORT_LIMIT };
    }
    // Registra também downloads Premium: são ilimitados enquanto o plano está ativo,
    // mas não apagam o histórico acumulado caso a conta volte ao Base.
    const id = crypto.randomUUID();
    if (isAccount) DB.prepare("INSERT INTO account_export_downloads(id, user_id, format, status, created_at) VALUES (?, ?, ?, 'reserved', ?)").run(id, userId, format, nowISO());
    else DB.prepare("INSERT INTO export_downloads(id, user_id, module, format, status, created_at) VALUES (?, ?, ?, ?, 'reserved', ?)").run(id, userId, module, format, nowISO());
    DB.exec('COMMIT');
    return { allowed: true, id, table };
  } catch (error) {
    DB.exec('ROLLBACK');
    throw error;
  }
}
function sendExportBuffer(res, file, headers, reservation) {
  if (reservation?.id) {
    const table = reservation.table === 'account_export_downloads' ? 'account_export_downloads' : 'export_downloads';
    res.once('finish', () => {
      try { DB.prepare(`UPDATE ${table} SET status = 'completed', completed_at = ? WHERE id = ? AND status = 'reserved'`).run(nowISO(), reservation.id); } catch { /* o download já foi enviado; registro fica auditável para reconciliação */ }
    });
    res.once('close', () => {
      if (!res.writableFinished) {
        try { DB.prepare(`DELETE FROM ${table} WHERE id = ? AND status = 'reserved'`).run(reservation.id); } catch { /* falha de conexão não deve derrubar o servidor */ }
      }
    });
  }
  res.writeHead(200, { ...headers, 'Content-Length': file.length, 'Cache-Control': 'no-store' });
  res.end(file);
}
function baseHistoryWindow(date = new Date()) {
  const floor = Plans.baseHistoryStartMonth(date);
  return { start: `${floor}-01`, endMonth: Plans.currentMonth(date) };
}
function enforceHistoryPlan(session, month, res) {
  if (Plans.planFor(session.user.plan) === 'premium') return true;
  if (!Plans.canViewHistoryMonth('base', month)) {
    sendError(res, 403, 'O mês selecionado está fora do período disponível.', { code: 'HISTORY_PERIOD_INVALID' });
    return false;
  }
  return true;
}
function nextDate(date, frequency) { return Finance.advanceRecurrence(date, frequency); }
function createDueRecurrences(userId) {
  const today = todayLocal();
  const rules = DB.prepare('SELECT * FROM recurrence_rules WHERE user_id = ? AND active = 1 AND next_date <= ? ORDER BY next_date').all(userId, today);
  if (!rules.length) return;
  DB.exec('BEGIN IMMEDIATE');
  try {
    const insert = DB.prepare(`INSERT OR IGNORE INTO expenses
      (id, user_id, recurrence_rule_id, occurrence_date, description, amount_cents, category, expense_date, due_date, status, payment_method, notes, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)`);
    const updateRule = DB.prepare('UPDATE recurrence_rules SET next_date = ?, updated_at = ? WHERE id = ? AND user_id = ?');
    for (const rule of rules) {
      let occurrence = rule.next_date;
      let generated = 0;
      while (occurrence <= today && generated < 120) {
        const plan = DB.prepare('SELECT plan FROM users WHERE id=?').get(userId)?.plan || 'base';
        const count = Number(DB.prepare('SELECT COUNT(*) AS total FROM expenses WHERE user_id=?').get(userId).total);
        // Recorrências permanecem ativas para ambos os planos: lançamentos são ilimitados.
        const timestamp = nowISO();
        insert.run(crypto.randomUUID(), userId, rule.id, occurrence, rule.description, rule.amount_cents, rule.category, occurrence, occurrence, rule.payment_method, rule.notes, timestamp, timestamp);
        occurrence = nextDate(occurrence, rule.frequency);
        generated += 1;
      }
      updateRule.run(occurrence, nowISO(), rule.id, userId);
    }
    DB.exec('COMMIT');
  } catch (error) {
    DB.exec('ROLLBACK'); throw error;
  }
}
function expenseFilters(userId, params) {
  const where = ['user_id = ?'];
  const values = [userId];
  if (params.get('month')) {
    let range;
    try { range = Finance.monthRange(params.get('month')); } catch { return { error: 'Mês inválido. Use AAAA-MM.' }; }
    where.push('expense_date >= ? AND expense_date <= ?'); values.push(range.start, range.end);
  }
  if (params.get('category')) {
    if (!CATEGORY_IDS.has(params.get('category'))) return { error: 'Categoria inválida.' };
    where.push('category = ?'); values.push(params.get('category'));
  }
  if (params.get('status')) {
    if (!STATUSES.has(params.get('status'))) return { error: 'Situação inválida.' };
    where.push('status = ?'); values.push(params.get('status'));
  }
  if (params.get('q')) {
    const q = params.get('q').trim().slice(0, 100);
    if (q) { where.push('description LIKE ? ESCAPE \'\\\''); values.push(`%${q.replace(/[\\%_]/g, '\\$&')}%`); }
  }
  const sorters = { date_desc: 'expense_date DESC, created_at DESC', date_asc: 'expense_date ASC, created_at ASC', amount_desc: 'amount_cents DESC, expense_date DESC', amount_asc: 'amount_cents ASC, expense_date DESC' };
  const sort = params.get('sort') || 'date_desc';
  if (!Object.hasOwn(sorters, sort)) return { error: 'Ordenação inválida.' };
  return { clause: where.join(' AND '), values, order: sorters[sort] };
}
function dashboard(userId, params = new URLSearchParams()) {
  createDueRecurrences(userId);
  const userPlan = DB.prepare('SELECT plan FROM users WHERE id = ?').get(userId)?.plan || 'base';
  const periodRange = parseDashboardRange(params, userPlan);
  if (periodRange.error) throw Object.assign(new Error(periodRange.error), { status: 400 });
  const { start, end, period } = periodRange;
  const month = end.slice(0, 7);
  const range = { start, end };
  const totals = DB.prepare(`SELECT COALESCE(SUM(amount_cents),0) AS total,
      COALESCE(SUM(CASE WHEN status='paid' THEN amount_cents ELSE 0 END),0) AS paid,
      COALESCE(SUM(CASE WHEN status='pending' THEN amount_cents ELSE 0 END),0) AS pending,
      COUNT(*) AS count
    FROM expenses WHERE user_id = ? AND expense_date BETWEEN ? AND ?`).get(userId, start, end);
  const premium = Plans.planFor(userPlan) === 'premium';
  const incoming = DB.prepare('SELECT COALESCE(SUM(amount_cents),0) AS total, COUNT(*) AS count FROM income_records WHERE user_id=? AND received_date BETWEEN ? AND ?').get(userId, start, end);
  const previousMonthDate = new Date(Date.UTC(Number(month.slice(0, 4)), Number(month.slice(5, 7)) - 2, 1));
  const previousMonth = `${previousMonthDate.getUTCFullYear()}-${String(previousMonthDate.getUTCMonth() + 1).padStart(2, '0')}`;
  const previousRange = Finance.monthRange(previousMonth);
  const previous = DB.prepare('SELECT COALESCE(SUM(amount_cents),0) AS total FROM expenses WHERE user_id = ? AND expense_date BETWEEN ? AND ?').get(userId, previousRange.start, previousRange.end);
  const previousIncome = DB.prepare('SELECT COALESCE(SUM(amount_cents),0) AS total FROM income_records WHERE user_id = ? AND received_date BETWEEN ? AND ?').get(userId, previousRange.start, previousRange.end);
  const categories = DB.prepare(`SELECT category, SUM(amount_cents) AS total, COUNT(*) AS count FROM expenses
    WHERE user_id = ? AND expense_date BETWEEN ? AND ? GROUP BY category ORDER BY total DESC`).all(userId, start, end);
  const upcoming = DB.prepare(`SELECT * FROM expenses WHERE user_id = ? AND status = 'pending' AND due_date IS NOT NULL ORDER BY due_date ASC, created_at ASC LIMIT 4`).all(userId).map(expenseRow);
  const recentExpenses = DB.prepare('SELECT * FROM expenses WHERE user_id = ? AND expense_date BETWEEN ? AND ? ORDER BY expense_date DESC, created_at DESC LIMIT 8').all(userId, start, end).map(expenseRow);
  const recentIncomes = DB.prepare(`SELECT i.*, b.institution AS bank_institution, b.account_label FROM income_records i JOIN bank_accounts b ON b.id=i.bank_account_id AND b.user_id=i.user_id WHERE i.user_id=? AND i.received_date BETWEEN ? AND ? ORDER BY i.received_date DESC,i.created_at DESC LIMIT 8`).all(userId, start, end).map(incomeRecordRow);
  const recentMovements = [
    ...recentExpenses.map((item) => ({ kind: 'expense', date: item.expenseDate, amountCents: item.amountCents, description: item.description, category: item.category, status: item.status, createdAt: item.createdAt })),
    ...recentIncomes.map((item) => ({ kind: 'income', date: item.receivedDate, amountCents: item.amountCents, description: item.description || item.source, source: item.source, bankInstitution: item.bankInstitution, payerName: item.payerName, createdAt: item.createdAt }))
  ].sort((a,b) => `${b.date}${b.createdAt}`.localeCompare(`${a.date}${a.createdAt}`)).slice(0, 4);
  const user = DB.prepare('SELECT monthly_income_cents, monthly_budget_cents FROM users WHERE id = ?').get(userId);
  const recurring = DB.prepare('SELECT id, description, amount_cents, category, frequency, next_date, active FROM recurrence_rules WHERE user_id = ? ORDER BY active DESC, next_date').all(userId).map((rule) => ({ id: rule.id, description: rule.description, amountCents: rule.amount_cents, category: rule.category, frequency: rule.frequency, nextDate: rule.next_date, active: Boolean(rule.active) }));
  const outCents = Number(totals.total || 0), inCents = Number(incoming.total || 0);
  return {
    month, period, range: { start, end }, today: todayLocal(),
    totals: { totalCents: outCents, paidCents: totals.paid, pendingCents: totals.pending, count: totals.count, incomingCents: inCents, outgoingCents: outCents, resultCents: inCents - outCents, incomeCount: Number(incoming.count || 0), expenseCount: Number(totals.count || 0), movementCount: Number(totals.count || 0) + Number(incoming.count || 0) },
    previousMonth: { month: previousMonth, totalCents: previous.total, incomingCents: Number(previousIncome.total || 0), resultCents: Number(previousIncome.total || 0) - Number(previous.total || 0) },
    categories: categories.map((row) => ({ category: row.category, totalCents: row.total, count: row.count })),
    upcoming, recent: recentExpenses, recentMovements, recurring,
    profile: { monthlyIncomeCents: user.monthly_income_cents, monthlyBudgetCents: user.monthly_budget_cents },
    availableCents: ((user.monthly_budget_cents || user.monthly_income_cents) - outCents)
  };
}

function serveStatic(pathname, req, res) {
  const mapped = STATIC_FILES.get(pathname);
  if (!mapped) { sendError(res, 404, 'Página não encontrada.'); return; }
  const filePath = path.join(PUBLIC_DIR, mapped[0]);
  let content;
  try { content = fs.readFileSync(filePath); }
  catch { sendError(res, 404, 'Arquivo não encontrado.'); return; }
  res.writeHead(200, {
    'Content-Type': mapped[1], 'Content-Length': content.length,
    'Cache-Control': mapped[0].endsWith('.html') ? 'no-cache' : 'public, max-age=300',
    ...(req.method === 'HEAD' ? {} : {})
  });
  res.end(req.method === 'HEAD' ? undefined : content);
}

async function handleRequest(req, res) {
  const securityHeaders = {
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy': "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'",
    'Cross-Origin-Resource-Policy': 'same-origin', 'X-DNS-Prefetch-Control': 'off'
  };
  for (const [key, value] of Object.entries(securityHeaders)) res.setHeader(key, value);
  res.setHeader('X-Powered-By', '');
  const baseOrigin = `http://${req.headers.host || `${HOST}:${PORT}`}`;
  let url;
  try { url = new URL(req.url, baseOrigin); } catch { sendError(res, 400, 'Endereço da requisição inválido.'); return; }
  const pathname = url.pathname;
  const method = req.method || 'GET';
  if (pathname === '/api/webhooks/mercadopago') { await handleMercadoPagoWebhook(req, res, url); return; }
  if (pathname.startsWith('/api/') && !REGISTRATION_COOLDOWN_ROUTES.has(pathname) && isRateLimited(req, pathname)) {
    res.setHeader('Retry-After', '60'); sendError(res, 429, 'Muitas tentativas em pouco tempo. Aguarde e tente novamente.'); return;
  }
  if (pathname === '/api/health' && method === 'GET') {
    sendJson(res, 200, { ok: true, application: 'OVBECK', database: 'sqlite', authentication: true, node: process.version }); return;
  }
  if (pathname === '/api/plans' && method === 'GET') {
    const billing = paymentConfiguration();
    sendJson(res, 200, { plans: Object.values(Plans.PLANS), paymentEnabled: paymentCheckoutAvailable(),
      checkoutAvailable: paymentCheckoutAvailable(), localPremiumAccess: LOCAL_PREMIUM_ACCESS, billingStage: LOCAL_PREMIUM_ACCESS ? 'local_access' : paymentCheckoutAvailable() ? 'ready_for_checkout' : 'configuration_required',
      premium: { amountCents: PREMIUM_PRICE_CENTS, currency: 'BRL', cycleDays: PREMIUM_CYCLE_DAYS, trialDays: PREMIUM_TRIAL_DAYS, provider: 'mercadopago' },
      futureFeatures: { aiFinancialAnalysis: { status: 'planned', available: false }, bankIntegration: { status: 'planned', available: false } } }); return;
  }
  if (pathname === '/api/auth/second-step' && method === 'POST') {
    if (!checkMutationProtection(req, res, null, { publicAuth: true })) return;
    if (!DEMO_SECOND_STEP) { sendError(res, 403, 'A verificação demonstrativa não está habilitada neste ambiente.'); return; }
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['challengeToken','code']) ||
        typeof body.challengeToken !== 'string' || !/^[a-f0-9]{64}$/i.test(body.challengeToken) ||
        typeof body.code !== 'string' || !/^\d{6}$/.test(body.code)) {
      sendError(res, 400, 'Informe exatamente seis números e utilize o desafio válido.'); return;
    }
    const tokenHash = hashToken(body.challengeToken);
    const stamp = nowISO();
    let userId = null;
    DB.exec('BEGIN IMMEDIATE');
    try {
      const record = DB.prepare(`SELECT c.user_id,c.attempts,u.account_status,u.demo_two_factor_enabled
        FROM demo_two_factor_challenges c JOIN users u ON u.id=c.user_id
        WHERE c.token_hash=? AND c.expires_at>?`).get(tokenHash,stamp);
      if (record && record.account_status === 'active' && record.demo_two_factor_enabled === 1 && record.attempts < 5) {
        userId = record.user_id;
        DB.prepare('DELETE FROM demo_two_factor_challenges WHERE token_hash=?').run(tokenHash);
      }
      DB.exec('COMMIT');
    } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
    if (!userId) { sendError(res, 401, 'Etapa expirada ou inválida. Entre com sua senha novamente.'); return; }
    const previous = parseCookie(req, 'ct_session');
    if (previous && /^[a-f0-9]{64}$/i.test(previous)) DB.prepare('DELETE FROM sessions WHERE token_hash=?').run(hashToken(previous));
    const account = DB.prepare('SELECT * FROM users WHERE id=?').get(userId);
    recordUserAccess(userId,req);
    const loginSession = createSession(userId);
    sendJson(res,200,{authenticated:true,admin:false,user:safePublicUser(account),csrfToken:loginSession.csrfToken,demo:true},{
      'Set-Cookie':[secureCookie(loginSession.token,Math.floor(SESSION_MS/1000)),clearCookie('gc_admin_session')]
    }); return;
  }
  if (pathname === '/api/account/second-step' && (method === 'GET' || method === 'PATCH')) {
    const session=requireSession(req,res);if(!session)return;
    if(method==='GET') {sendJson(res,200,{enabled:Boolean(session.user.demo_two_factor_enabled),demoAvailable:DEMO_SECOND_STEP,realDeliveryConfigured:false});return;}
    if(!checkMutationProtection(req,res,session))return;
    if(!DEMO_SECOND_STEP){sendError(res,403,'A verificação demonstrativa está disponível somente na instalação local de desenvolvimento.');return;}
    const body=await readJson(req);
    if(!isPlainObject(body)||!hasOnlyKeys(body,['enabled'])||typeof body.enabled!=='boolean') {sendError(res,400,'Informe a opção de segurança desejada.');return;}
    DB.prepare('UPDATE users SET demo_two_factor_enabled=?,updated_at=? WHERE id=?').run(body.enabled?1:0,nowISO(),session.user.id);
    if(!body.enabled) DB.prepare('DELETE FROM demo_two_factor_challenges WHERE user_id=?').run(session.user.id);
    sendJson(res,200,{enabled:body.enabled,demoAvailable:true,realDeliveryConfigured:false});return;
  }
  if (pathname === '/api/auth/session' && method === 'GET') {
    const adminSession = adminSessionForRequest(req);
    if (adminSession) { sendJson(res, 200, { authenticated: true, admin: true, adminUser: adminSession.admin, mustChangePassword: adminSession.mustChangePassword, mustCompleteProfile: adminSession.mustCompleteProfile, csrfToken: adminSession.csrfToken }); return; }
    const session = sessionForRequest(req);
    sendJson(res, 200, session ? { authenticated: true, admin: false, user: session.publicUser, csrfToken: session.csrfToken } : { authenticated: false, admin: false, user: null, csrfToken: null }); return;
  }

  if (pathname.startsWith('/api/admin/')) {
    const handled = await handleAdminApi(req, res, url, pathname, method);
    if (handled) return;
  }

  if (pathname === '/api/auth/password-reset' && method === 'POST') {
    if (!checkMutationProtection(req, res, null, { publicAuth: true })) return;
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['token', 'password', 'confirmPassword']) ||
        typeof body.token !== 'string' || !/^[a-f0-9]{64}$/i.test(body.token) ||
        !validateText(body.password, 128, true) || !isValidNewPassword(body.password) || body.password !== body.confirmPassword) {
      sendError(res, 400, 'Informe um link válido, uma nova senha com os requisitos indicados e a confirmação correspondente.'); return;
    }
    const nextPassword = await hashPassword(body.password);
    const tokenHash = hashToken(body.token);
    const stamp = nowISO();
    DB.exec('BEGIN IMMEDIATE');
    try {
      const reset = DB.prepare(`SELECT t.id, t.user_id FROM client_password_reset_tokens t
        JOIN users u ON u.id = t.user_id
        WHERE t.token_hash = ? AND t.used_at IS NULL AND t.expires_at > ? AND u.account_status = 'active'`).get(tokenHash, stamp);
      if (!reset) {
        DB.exec('ROLLBACK');
        sendError(res, 410, 'Este link de redefinição expirou, já foi utilizado ou não está mais disponível. Solicite um novo link ao administrador.'); return;
      }
      DB.prepare('UPDATE users SET password_salt = ?, password_hash = ?, updated_at = ? WHERE id = ?')
        .run(nextPassword.salt, nextPassword.hash, stamp, reset.user_id);
      DB.prepare('DELETE FROM sessions WHERE user_id = ?').run(reset.user_id);
      DB.prepare('UPDATE client_password_reset_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL').run(stamp, reset.id);
      DB.exec('COMMIT');
    } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
    sendJson(res, 200, { changed: true, message: 'Senha redefinida. Entre novamente com sua nova senha.' });
    return;
  }

  if (pathname === '/api/auth/register-intent' && method === 'POST') {
    if (!checkMutationProtection(req, res, null, { publicAuth: true })) return;
    const body = await readJson(req);
    if (!hasOnlyKeys(body, ['fullName', 'email', 'password', 'confirmPassword'])) { sendError(res, 400, 'A solicitação contém campos não permitidos.'); return; }
    const validationError = validateNewUser(body);
    if (validationError) {
      const attempt = registerInvalidRegistrationAttempt(body);
      if (attempt.blocked) sendError(res, 429, 'Não foi possível concluir o cadastro com essas informações. Revise os campos e altere os dados antes de tentar novamente.', { code: 'REGISTRATION_INVALID_REPEAT', attempts: attempt.attempts });
      else sendError(res, 400, validationError, { code: 'REGISTRATION_VALIDATION_FAILED', attempts: attempt.attempts });
      return;
    }
    clearInvalidRegistrationAttempt(body);
    const email = normalizeEmail(body.email);
    if (DB.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE').get(email) || DB.prepare('SELECT id FROM admin_users WHERE email = ? COLLATE NOCASE').get(email)) { sendError(res, 409, 'Já existe uma conta com esse e-mail. Entre ou use outro endereço.'); return; }
    const registrationGate = registrationIpGate(req);
    if (registrationIpBlockedResponse(res, registrationGate)) return;
    DB.prepare('DELETE FROM pending_registrations WHERE expires_at <= ?').run(nowISO());
    if (DB.prepare('SELECT token_hash FROM pending_registrations WHERE email = ? COLLATE NOCASE AND expires_at > ?').get(email, nowISO())) {
      sendError(res, 409, 'Já existe uma escolha de plano pendente para este e-mail. Volte ao fluxo ou aguarde a expiração.'); return;
    }
    const cooldownStatus = activeRegistrationCooldown(req);
    if (cooldownStatus.blocked) { sendRegistrationCooldownError(res, cooldownStatus); return; }
    const password = await hashPassword(body.password);
    const token = crypto.randomBytes(32).toString('hex');
    const stamp = nowISO();
    const expires = new Date(Date.now() + 20 * 60_000).toISOString();
    DB.exec('BEGIN IMMEDIATE');
    try {
      // Só solicitações de cadastro completas e válidas contam como tentativa.
      // A contagem e a criação da intenção são atômicas: erro interno não consome tentativa.
      const cooldown = registrationCooldownState(req, stamp, true);
      if (cooldown.blocked) {
        DB.exec('COMMIT');
        sendRegistrationCooldownError(res, cooldown);
        return;
      }
      DB.prepare(`INSERT INTO pending_registrations(token_hash, full_name, email, password_salt, password_hash, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`).run(hashToken(token), normalizeFullName(body.fullName), email, password.salt, password.hash, stamp, expires);
      DB.exec('COMMIT');
    } catch (error) {
      try { DB.exec('ROLLBACK'); } catch {}
      throw error;
    }
    sendJson(res, 201, { created: false, intentToken: token, expiresAt: expires, message: 'Cadastro validado. Escolha um plano para concluir a criação da conta.' });
    return;
  }

  if (pathname === '/api/auth/register-intent/update' && method === 'POST') {
    if (!checkMutationProtection(req, res, null, { publicAuth: true })) return;
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['intentToken', 'fullName', 'email', 'password', 'confirmPassword']) || typeof body.intentToken !== 'string' || !/^[a-f0-9]{64}$/.test(body.intentToken)) {
      sendError(res, 400, 'Os dados temporários do cadastro são inválidos.'); return;
    }
    const credentials = { fullName: body.fullName, email: body.email, password: body.password, confirmPassword: body.confirmPassword };
    const validationError = validateNewUser(credentials);
    if (validationError) {
      const attempt = registerInvalidRegistrationAttempt(credentials);
      if (attempt.blocked) sendError(res, 429, 'Não foi possível concluir o cadastro com essas informações. Revise os campos e altere os dados antes de tentar novamente.', { code: 'REGISTRATION_INVALID_REPEAT', attempts: attempt.attempts });
      else sendError(res, 400, validationError, { code: 'REGISTRATION_VALIDATION_FAILED', attempts: attempt.attempts });
      return;
    }
    clearInvalidRegistrationAttempt(credentials);
    const email = normalizeEmail(body.email);
    const password = await hashPassword(body.password);
    const tokenHash = hashToken(body.intentToken);
    const stamp = nowISO();
    const expires = new Date(Date.now() + 20 * 60_000).toISOString();
    DB.exec('BEGIN IMMEDIATE');
    try {
      const intent = DB.prepare('SELECT token_hash FROM pending_registrations WHERE token_hash = ? AND expires_at > ?').get(tokenHash, stamp);
      if (!intent) {
        DB.exec('ROLLBACK');
        sendError(res, 410, 'A etapa de cadastro expirou. Preencha os dados novamente.'); return;
      }
      if (DB.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE').get(email) || DB.prepare('SELECT id FROM admin_users WHERE email = ? COLLATE NOCASE').get(email)) {
        DB.exec('ROLLBACK');
        sendError(res, 409, 'Já existe uma conta com esse e-mail. Entre ou use outro endereço.'); return;
      }
      if (DB.prepare('SELECT token_hash FROM pending_registrations WHERE email = ? COLLATE NOCASE AND token_hash <> ? AND expires_at > ?').get(email, tokenHash, stamp)) {
        DB.exec('ROLLBACK');
        sendError(res, 409, 'Já existe outra escolha de plano pendente para esse e-mail.'); return;
      }
      DB.prepare(`UPDATE pending_registrations SET full_name = ?, email = ?, password_salt = ?, password_hash = ?, expires_at = ? WHERE token_hash = ?`)
        .run(normalizeFullName(body.fullName), email, password.salt, password.hash, expires, tokenHash);
      DB.exec('COMMIT');
    } catch (error) {
      try { DB.exec('ROLLBACK'); } catch { /* transação já finalizada */ }
      if (String(error.message).includes('UNIQUE')) { sendError(res, 409, 'Já existe uma conta ou cadastro pendente com esse e-mail.'); return; }
      throw error;
    }
    sendJson(res, 200, { updated: true, intentToken: body.intentToken, expiresAt: expires, message: 'Dados temporários atualizados. Escolha um plano para concluir o cadastro.' });
    return;
  }

  if (pathname === '/api/auth/register-intent/cancel' && method === 'POST') {
    if (!checkMutationProtection(req, res, null, { publicAuth: true })) return;
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['intentToken']) || typeof body.intentToken !== 'string' || !/^[a-f0-9]{64}$/.test(body.intentToken)) { sendError(res, 400, 'Token temporário inválido.'); return; }
    DB.prepare('DELETE FROM pending_registrations WHERE token_hash = ?').run(hashToken(body.intentToken));
    sendJson(res, 200, { ok: true }); return;
  }

  if (pathname === '/api/auth/register/complete' && method === 'POST') {
    if (!checkMutationProtection(req, res, null, { publicAuth: true })) return;
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['intentToken', 'plan', 'trialConsent', 'billing']) || typeof body.intentToken !== 'string' || !/^[a-f0-9]{64}$/.test(body.intentToken) || !['base', 'premium'].includes(body.plan)) {
      sendError(res, 400, 'Escolha um plano válido para concluir o cadastro.'); return;
    }
    if (body.plan === 'premium' && body.trialConsent !== true) { sendError(res, 400, 'Confirme que leu as condições do plano Premium para continuar.'); return; }
    if (body.plan === 'premium' && !LOCAL_PREMIUM_ACCESS) {
      sendError(res, 503, 'A etapa de pagamento real ainda não está habilitada. Nenhuma conta Premium foi criada e nenhuma cobrança foi realizada.', { code: 'PREMIUM_CHECKOUT_UNAVAILABLE' }); return;
    }
    if (body.plan === 'premium') {
      const pendingForValidation = DB.prepare('SELECT email FROM pending_registrations WHERE token_hash=? AND expires_at>?').get(hashToken(body.intentToken), nowISO());
      if (!pendingForValidation) { sendError(res, 410, 'A etapa de cadastro expirou. Preencha os dados novamente.'); return; }
      const billingError = validateCheckoutBilling(body.billing, pendingForValidation.email);
      if (billingError) { sendError(res, 400, billingError); return; }
    } else if (body.billing !== undefined && (!isPlainObject(body.billing) || Object.keys(body.billing).length !== 0)) {
      sendError(res, 400, 'O plano Base não exige dados de cobrança.'); return;
    }
    const stamp = nowISO();
    let createdUserId = null;
    const registrationGate = registrationIpGate(req);
    if (registrationIpBlockedResponse(res, registrationGate)) return;
    DB.exec('BEGIN IMMEDIATE');
    try {
      const intent = DB.prepare('SELECT * FROM pending_registrations WHERE token_hash = ? AND expires_at > ?').get(hashToken(body.intentToken), stamp);
      if (!intent) { DB.exec('ROLLBACK'); sendError(res, 410, 'A etapa de cadastro expirou. Preencha os dados novamente.'); return; }
      if (DB.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE').get(intent.email) || DB.prepare('SELECT id FROM admin_users WHERE email = ? COLLATE NOCASE').get(intent.email)) {
        DB.exec('ROLLBACK'); sendError(res, 409, 'Já existe uma conta com esse e-mail. Entre ou use outro endereço.'); return;
      }
      let activeRelease = null;
      if (registrationGate.enabled) {
        const counter = DB.prepare('SELECT successful_creations FROM registration_ip_counters WHERE ip_hash = ?').get(registrationGate.ipHash);
        const count = Number(counter?.successful_creations || 0);
        if (count >= 3) {
          activeRelease = DB.prepare(`SELECT id, remaining_uses FROM registration_ip_releases WHERE ip_hash=? AND status='active' AND remaining_uses>0 AND (expires_at IS NULL OR expires_at>?) ORDER BY created_at DESC LIMIT 1`).get(registrationGate.ipHash, stamp);
          if (!activeRelease) { DB.exec('ROLLBACK'); sendError(res, 429, 'Limite de criação de contas atingido. Entre em uma conta existente ou solicite análise ao suporte.', { code: 'REGISTRATION_IP_LIMIT_REACHED', limit: 3 }); return; }
        }
      }
      createdUserId = crypto.randomUUID();
      const selectedPlan = body.plan === 'premium' ? 'premium' : 'base';
      const selectedPlanStatus = selectedPlan === 'premium' ? 'legacy' : 'free';
      const selectedSubscriptionStatus = selectedPlan === 'premium' ? 'local_access' : 'none';
      const billing = body.plan === 'premium' ? body.billing : null;
      DB.prepare(`INSERT INTO users(id, full_name, email, password_salt, password_hash, plan, plan_status, premium_subscription_status, plan_started_at,
        billing_full_name, billing_phone, billing_cep, billing_street, billing_number, billing_district, billing_city, billing_state, billing_complement,
        created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(createdUserId, intent.full_name, intent.email, intent.password_salt, intent.password_hash, selectedPlan, selectedPlanStatus, selectedSubscriptionStatus,
          selectedPlan === 'premium' ? stamp : null, billing?.fullName || '', billing?.phone || '', billing?.cep || '', billing?.street || '', billing?.number || '',
          billing?.district || '', billing?.city || '', billing?.state || '', billing?.complement || '', stamp, stamp);
      DB.prepare('DELETE FROM pending_registrations WHERE token_hash = ?').run(hashToken(body.intentToken));
      if (registrationGate.enabled) {
        const encryptedIp = encryptRegistrationIp(requestIp(req));
        DB.prepare(`INSERT INTO registration_ip_counters(ip_hash, successful_creations, first_created_at, last_created_at, last_ip_encrypted) VALUES (?,1,?,?,?)
          ON CONFLICT(ip_hash) DO UPDATE SET successful_creations=successful_creations+1,last_created_at=excluded.last_created_at,last_ip_encrypted=COALESCE(excluded.last_ip_encrypted,registration_ip_counters.last_ip_encrypted)`)
          .run(registrationGate.ipHash, stamp, stamp, encryptedIp);
        if (activeRelease) DB.prepare(`UPDATE registration_ip_releases SET remaining_uses=remaining_uses-1,status=CASE WHEN remaining_uses-1<=0 THEN 'exhausted' ELSE 'active' END,last_used_at=?,updated_at=? WHERE id=? AND status='active' AND remaining_uses>0`).run(stamp, stamp, activeRelease.id);
      }
      DB.exec('COMMIT');
    } catch (error) {
      try { DB.exec('ROLLBACK'); } catch {}
      if (String(error.message).includes('UNIQUE')) { sendError(res, 409, 'Já existe uma conta ou cadastro pendente com esse e-mail.'); return; }
      throw error;
    }
    const imported = importLegacyExpenses(DB, createdUserId);
    const finalUser = DB.prepare('SELECT plan, plan_status FROM users WHERE id=?').get(createdUserId);
    const firstBillingDate = finalUser.plan === 'premium' ? plusDaysIso(stamp, PREMIUM_TRIAL_DAYS).slice(0, 10) : null;
    sendJson(res, 201, { created: true, authenticated: false, plan: finalUser.plan,
      planStatus: finalUser.plan_status, checkoutUrl: null, trialDays: finalUser.plan === 'premium' ? PREMIUM_TRIAL_DAYS : 0,
      firstBillingDate, paymentStage: 'not_processed',
      message: finalUser.plan === 'premium'
        ? 'Etapa local concluída. O Premium foi habilitado para avaliação nesta instalação; nenhum cartão foi enviado ao servidor e nenhuma cobrança ou assinatura foi criada. A data exibida é apenas indicativa para uma futura integração.'
        : 'Plano Base confirmado por R$ 0,00. Conta criada com sucesso. Entre com seu e-mail e sua senha para começar.',
      legacyImport: imported.imported, legacyWarning: imported.warning });
    return;
  }

  if (pathname === '/api/auth/register' && method === 'POST') {
    sendError(res, 410, 'O cadastro agora exige duas etapas. Use o fluxo /api/auth/register-intent, escolha Base ou Premium e confirme para criar a conta.', { code: 'REGISTRATION_PLAN_REQUIRED' });
    return;
  }

  if (pathname === '/api/auth/login' && method === 'POST') {
    if (!checkMutationProtection(req, res, null, { publicAuth: true })) return;
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['email', 'password']) || !validateText(body.email, 254, true) || !validateText(body.password, 128, true)) { sendError(res, 400, 'Informe e-mail e senha.'); return; }
    const email = normalizeEmail(body.email);
    const admin = DB.prepare("SELECT * FROM admin_users WHERE email = ? COLLATE NOCASE AND role = 'admin'").get(email);
    if (admin) {
      if (adminLoginIsLocked(email, req)) { res.setHeader('Retry-After', '900'); sendError(res, 429, 'Acesso administrativo temporariamente bloqueado após tentativas inválidas.'); return; }
      const validAdmin = admin.is_active === 1 && await verifyAdminPassword(body.password, admin.password_salt, admin.password_hash);
      if (!validAdmin) {
        const attempt = registerAdminLoginFailure(email, req);
        if (attempt.locked) { res.setHeader('Retry-After', '900'); sendError(res, 429, 'Acesso administrativo temporariamente bloqueado após tentativas inválidas.'); }
        else sendError(res, 401, 'E-mail ou senha incorretos.');
        return;
      }
      clearAdminLoginFailures(email, req);
      const previousClientToken = parseCookie(req, 'ct_session');
      if (previousClientToken && /^[a-f0-9]{64}$/.test(previousClientToken)) DB.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(previousClientToken));
      const previousAdminToken = parseCookie(req, 'gc_admin_session');
      if (previousAdminToken && /^[a-f0-9]{64}$/.test(previousAdminToken)) {
        const previousAdminTokenHash = hashToken(previousAdminToken);
        const activeSession = DB.prepare(`SELECT csrf_token, expires_at FROM admin_sessions
          WHERE token_hash = ? AND admin_user_id = ? AND expires_at > ?`).get(previousAdminTokenHash, admin.id, nowISO());
        if (activeSession) {
          // Reenvio do formulário durante uma sessão ativa não é uma nova autenticação.
          // Mantém a sessão existente e evita gerar eventos repetidos de login.
          DB.prepare('UPDATE admin_sessions SET last_seen_at = ? WHERE token_hash = ?').run(nowISO(), previousAdminTokenHash);
          const remainingSeconds = Math.max(1, Math.floor((Date.parse(activeSession.expires_at) - Date.now()) / 1000));
          sendJson(res, 200, { authenticated: true, admin: true, mustChangePassword: Boolean(admin.must_change_password), mustCompleteProfile: !Boolean(admin.profile_configured), adminUser: { id: admin.id, fullName: admin.full_name, email: admin.email, role: 'admin' }, csrfToken: activeSession.csrf_token }, {
            'Set-Cookie': [secureCookie(previousAdminToken, remainingSeconds, 'gc_admin_session'), clearCookie('ct_session')]
          });
          return;
        }
        DB.prepare('DELETE FROM admin_sessions WHERE token_hash = ?').run(previousAdminTokenHash);
      }
      const adminSession = createAdminSession(admin.id);
      const loginAudit = { admin: { id: admin.id }, csrfToken: adminSession.csrfToken };
      writeAdminAudit(loginAudit, 'admin_login', null, {}, req);
      sendJson(res, 200, { authenticated: true, admin: true, mustChangePassword: Boolean(admin.must_change_password), mustCompleteProfile: !Boolean(admin.profile_configured), adminUser: { id: admin.id, fullName: admin.full_name, email: admin.email, role: 'admin' }, csrfToken: adminSession.csrfToken }, {
        'Set-Cookie': [secureCookie(adminSession.token, Math.floor(ADMIN_SESSION_MS / 1000), 'gc_admin_session'), clearCookie('ct_session')]
      });
      return;
    }
    const user = DB.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE').get(email);
    if (!user) {
      const deletedHash = crypto.createHmac('sha256', REGISTRATION_IP_HMAC_KEY).update('deleted-account-notice-v1:').update(email).digest('hex');
      const deletedNotice = DB.prepare('SELECT deleted_at FROM deleted_account_notices WHERE email_hash=? AND expires_at>?').get(deletedHash, nowISO());
      if (deletedNotice) { sendError(res, 410, 'Sua conta foi excluída por um administrador. Caso considere que ocorreu algum erro, entre em contato com a OVBECK para obter esclarecimentos.', { code: 'ACCOUNT_DELETED_BY_ADMIN' }); return; }
    }
    if (user && user.account_status === 'active') {
      resetExpiredLoginLock(user);
      const refreshedUser = DB.prepare('SELECT * FROM users WHERE id=?').get(user.id);
      const lock = loginLockState(refreshedUser);
      if (lock.locked) { res.setHeader('Retry-After', String(lock.remainingSeconds)); sendError(res, 423, 'Conta temporariamente bloqueada por segurança. Aguarde o encerramento do período ou solicite suporte.', { code: 'LOGIN_ACCOUNT_LOCKED', retryAfterSeconds: lock.remainingSeconds, lockedUntil: lock.until }); return; }
      const short = activeShortLoginBlock(user.id, req);
      if (short.blocked) { res.setHeader('Retry-After', String(short.remainingSeconds)); sendError(res, 429, 'Detectamos várias tentativas de acesso com credenciais incorretas. Aguarde antes de tentar novamente.', { code: 'LOGIN_SHORT_COOLDOWN', retryAfterSeconds: short.remainingSeconds, warningAfterCooldown: true }); return; }
      const valid = await verifyPassword(body.password, user.password_salt, user.password_hash);
      if (!valid) {
        const attempt = recordClientLoginFailure(user.id, req);
        if (attempt.locked) { res.setHeader('Retry-After', String(attempt.remainingSeconds)); sendError(res, 423, 'Conta temporariamente bloqueada. Por segurança, o acesso foi suspenso por uma hora.', { code: 'LOGIN_ACCOUNT_LOCKED', retryAfterSeconds: attempt.remainingSeconds, lockedUntil: attempt.until }); }
        else if (attempt.shortBlocked) { res.setHeader('Retry-After', String(attempt.remainingSeconds)); sendError(res, 429, 'Detectamos várias tentativas de acesso com credenciais incorretas. Aguarde antes de tentar novamente.', { code: 'LOGIN_SHORT_COOLDOWN', retryAfterSeconds: attempt.remainingSeconds, warningAfterCooldown: true }); }
        else sendError(res, 401, 'E-mail ou senha incorretos.', { ...(attempt.warning ? { warning: attempt.attemptsAfterCooldown === 1 ? 'Atenção: mais uma tentativa incorreta poderá resultar em bloqueio temporário por uma hora.' : 'Atenção: mais duas tentativas incorretas poderão resultar no bloqueio temporário desta conta por uma hora.' } : {}) });
        return;
      }
      clearClientLoginFailures(user.id);
    } else {
      // Para e-mails inexistentes, não revelar se há cadastro e não criar bloqueios de conta.
      await verifyPassword(body.password, '00'.repeat(16), '00'.repeat(64));
      sendError(res, 401, 'E-mail ou senha incorretos.'); return;
    }
    if (user.demo_two_factor_enabled === 1) {
      if (!DEMO_SECOND_STEP) {
        sendError(res,403,'A conta exige a segunda etapa, ainda não integrada ao ambiente atual. Consulte o administrador.',{code:'SECOND_STEP_NOT_CONFIGURED'});return;
      }
      const challengeToken=crypto.randomBytes(32).toString('hex');
      DB.prepare('DELETE FROM demo_two_factor_challenges WHERE user_id=? OR expires_at<=?').run(user.id,nowISO());
      DB.prepare('INSERT INTO demo_two_factor_challenges(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)')
        .run(hashToken(challengeToken),user.id,nowISO(),new Date(Date.now()+5*60*1000).toISOString());
      sendJson(res,200,{authenticated:false,requiresTwoFactor:true,challengeToken,email:user.email,demo:true,message:'Verificação demonstrativa: digite seis números. Nenhum código foi enviado por e-mail.'});return;
    }
    const previousToken = parseCookie(req, 'ct_session');
    if (previousToken && /^[a-f0-9]{64}$/.test(previousToken)) DB.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(previousToken));
    const previousAdminToken = parseCookie(req, 'gc_admin_session');
    if (previousAdminToken && /^[a-f0-9]{64}$/.test(previousAdminToken)) DB.prepare('DELETE FROM admin_sessions WHERE token_hash = ?').run(hashToken(previousAdminToken));
    const authenticatedUser = DB.prepare('SELECT * FROM users WHERE email=? COLLATE NOCASE').get(email);
    recordUserAccess(authenticatedUser.id, req);
    const session = createSession(authenticatedUser.id);
    sendJson(res, 200, { authenticated: true, admin: false, user: safePublicUser(authenticatedUser), csrfToken: session.csrfToken }, {
      'Set-Cookie': [secureCookie(session.token, Math.floor(SESSION_MS / 1000)), clearCookie('gc_admin_session')]
    });
    return;
  }

  if (!['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    res.setHeader('Allow', 'GET, HEAD, POST, PATCH, DELETE'); sendError(res, 405, 'Método não permitido.'); return;
  }
  if (method === 'GET' || method === 'HEAD') {
    if (pathname === '/api/sync/revision') {
      const clientToken = parseCookie(req, 'ct_session');
      if (clientToken && /^[a-f0-9]{64}$/i.test(clientToken)) {
        const revoked = DB.prepare('SELECT token_hash FROM revoked_account_sessions WHERE token_hash=? AND expires_at>?').get(hashToken(clientToken), nowISO());
        if (revoked) { sendJson(res, 410, { error: 'Sua conta foi excluída por um administrador. Caso considere que ocorreu algum erro, entre em contato com a OVBECK para obter esclarecimentos.', code: 'ACCOUNT_DELETED_BY_ADMIN' }, { 'Set-Cookie': clearCookie('ct_session') }); return; }
      }
      const session = requireSession(req, res); if (!session) return;
      const row = DB.prepare('SELECT revision, updated_at FROM app_sync_state WHERE id=1').get();
      sendJson(res, 200, { revision: Number(row?.revision || 0), updatedAt: row?.updated_at || null, userId: session.user.id }); return;
    }
    if (pathname === '/api/account/notifications') {
      const session = requireSession(req, res); if (!session) return;
      const notifications = DB.prepare('SELECT id,kind,message,created_at AS createdAt FROM account_notifications WHERE user_id=? AND read_at IS NULL ORDER BY created_at ASC LIMIT 20').all(session.user.id);
      sendJson(res, 200, { notifications }); return;
    }
    if (pathname === '/api/profile') {
      const session = requireSession(req, res); if (!session) return;
      sendJson(res, 200, session.publicUser); return;
    }
    if (pathname === '/api/account/details') {
      const session = requireSession(req, res); if (!session) return;
      const row = DB.prepare(`SELECT full_name, email, created_at, billing_full_name, billing_phone,
        billing_cep, billing_street, billing_number, billing_district, billing_city, billing_state, billing_complement,
        profile_photo_mime, profile_photo_updated_at FROM users WHERE id=? AND account_status='active'`).get(session.user.id);
      if (!row) { sendError(res, 404, 'Conta não encontrada.'); return; }
      sendJson(res, 200, { fullName: row.full_name, email: row.email, createdAt: row.created_at,
        phone: row.billing_phone || '', cpf: null, address: row.billing_street || '', number: row.billing_number || '',
        complement: row.billing_complement || '', district: row.billing_district || '', city: row.billing_city || '',
        state: row.billing_state || '', postalCode: row.billing_cep || '', hasProfilePhoto: Boolean(row.profile_photo_mime),
        profilePhotoUpdatedAt: row.profile_photo_updated_at || null }); return;
    }
    if (pathname === '/api/profile/photo') {
      const session = requireSession(req, res); if (!session) return;
      const targetId = String(url.searchParams.get('userId') || session.user.id);
      if (targetId !== session.user.id) {
        const allowed = linkedAccountsFor(session.user).accounts.some((account) => account.id === targetId);
        if (!allowed) { sendError(res, 404, 'Imagem de perfil não encontrada.'); return; }
      }
      const row = DB.prepare(`SELECT profile_photo, profile_photo_mime FROM users WHERE id=? AND account_status='active'`).get(targetId);
      if (!row?.profile_photo || !row.profile_photo_mime) { sendError(res, 404, 'Imagem de perfil não cadastrada.'); return; }
      const image = Buffer.from(row.profile_photo);
      res.writeHead(200, { 'Content-Type': row.profile_photo_mime, 'Content-Length': image.length,
        'Cache-Control': 'private, no-store, max-age=0', 'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; sandbox" });
      res.end(image); return;
    }
    if (pathname === '/api/accounts/linked' && method === 'GET') {
      const session = requireSession(req, res); if (!session) return;
      sendJson(res, 200, linkedAccountsFor(session.user)); return;
    }
  if (pathname === '/api/plan/usage') {
      const session = requireSession(req, res); if (!session) return;
      const plan = Plans.planFor(session.user.plan);
      const calculationCount = Number(DB.prepare('SELECT COUNT(*) AS total FROM installment_calculations WHERE user_id = ?').get(session.user.id).total);
      const window = baseHistoryWindow();
      const expenseCount = Number(DB.prepare('SELECT COUNT(*) AS total FROM expenses WHERE user_id=?').get(session.user.id).total);
      const receivedCount = Number(DB.prepare('SELECT COUNT(*) AS total FROM income_records WHERE user_id=?').get(session.user.id).total);
      sendJson(res, 200, { plan, expenseCount, expenseLimit: null, receivedCount, receivedLimit: null, planStatus: session.user.premium_subscription_status === 'local_access' ? 'local' : (session.user.plan_status || (plan === 'premium' ? 'legacy' : 'free')), planStartedAt: session.user.plan_started_at || null, planExpiresAt: session.user.plan_expires_at || null,
        daysUntilExpiry: session.user.plan === 'premium' ? daysUntilExpiry(session.user.premium_trial_ends_at || session.user.plan_expires_at) : null,
        premiumSubscriptionStatus: session.user.premium_subscription_status || 'none',
        premiumNextPaymentAt: session.user.premium_next_payment_at || null,
        premiumPriceCents: PREMIUM_PRICE_CENTS, premiumCycleDays: PREMIUM_CYCLE_DAYS, premiumTrialDays: PREMIUM_TRIAL_DAYS,
        realPaymentGatewayConfigured: paymentCheckoutAvailable(), automaticRenewalEnabled: paymentCheckoutAvailable() && ['pending','trialing','active','past_due'].includes(session.user.premium_subscription_status), hideExpiryNotice: Boolean(session.user.hide_expiry_notice), paymentEnabled: paymentCheckoutAvailable(), paymentProvider: 'mercadopago',
        baseHistoryStartMonth: window.start.slice(0, 7), currentMonth: window.endMonth, calculationCount, calculationLimit: plan === 'premium' ? null : Plans.BASE_CALCULATION_LIMIT, exports: exportUsage(session.user.id) }); return;
    }
    if (pathname === '/api/dashboard') {
      const session = requireSession(req, res); if (!session) return;
      try { sendJson(res, 200, dashboard(session.user.id, url.searchParams)); } catch (error) { sendError(res, error.status || 500, error.message || 'Não foi possível calcular a visão geral.'); } return;
    }
    if (pathname === '/api/expenses') {
      const session = requireSession(req, res); if (!session) return;
      createDueRecurrences(session.user.id);
      const filters = expenseFilters(session.user.id, url.searchParams);
      if (filters.error) { sendError(res, 400, filters.error); return; }
      const rows = DB.prepare(`SELECT * FROM expenses WHERE ${filters.clause} ORDER BY ${filters.order} LIMIT 1000`).all(...filters.values).map(expenseRow);
      sendJson(res, 200, { expenses: rows, categories: CATEGORIES }); return;
    }
    if (pathname === '/api/upcoming') {
      const session = requireSession(req, res); if (!session) return;
      createDueRecurrences(session.user.id);
      const params = url.searchParams;
      const where = ['user_id=?', 'due_date IS NOT NULL']; const values = [session.user.id];
      if (params.get('category')) {
        if (!CATEGORY_IDS.has(params.get('category'))) { sendError(res, 400, 'Categoria inválida.'); return; }
        where.push('category=?'); values.push(params.get('category'));
      }
      if (params.get('month')) {
        let range; try { range = Finance.monthRange(params.get('month')); } catch { sendError(res, 400, 'Mês inválido. Use AAAA-MM.'); return; }
        where.push('due_date BETWEEN ? AND ?'); values.push(range.start, range.end);
      }
      const q = String(params.get('q') || '').trim().slice(0, 100);
      if (q) { where.push("description LIKE ? ESCAPE '\\'"); values.push(`%${q.replace(/[\%_]/g, '\$&')}%`); }
      const sort = params.get('sort') === 'farthest' ? 'DESC' : 'ASC';
      const rows = DB.prepare(`SELECT * FROM expenses WHERE ${where.join(' AND ')} ORDER BY CASE WHEN status='paid' THEN 1 ELSE 0 END ASC, due_date ${sort}, created_at DESC`).all(...values).map(expenseRow);
      const pending = rows.filter((item) => item.status !== 'paid');
      const completed = rows.filter((item) => item.status === 'paid');
      sendJson(res, 200, { pending, completed, totalPending: pending.length, totalCompleted: completed.length, categories: CATEGORIES }); return;
    }
    if (pathname === '/api/recurrences') {
      const session = requireSession(req, res); if (!session) return;
      const rules = DB.prepare('SELECT * FROM recurrence_rules WHERE user_id = ? ORDER BY active DESC, next_date').all(session.user.id).map((r) => ({ id: r.id, description: r.description, amountCents: r.amount_cents, category: r.category, frequency: r.frequency, nextDate: r.next_date, active: Boolean(r.active) }));
      sendJson(res, 200, { recurrences: rules }); return;
    }
    if (pathname === '/api/calculations') {
      const session = requireSession(req, res); if (!session) return;
      sendJson(res, 200, { calculations: DB.prepare('SELECT * FROM installment_calculations WHERE user_id = ? ORDER BY created_at DESC').all(session.user.id).map(calculationRow), plan: Plans.planFor(session.user.plan), limit: Plans.planFor(session.user.plan) === 'premium' ? null : Plans.BASE_CALCULATION_LIMIT }); return;
    }
    if (pathname === '/api/history') {
      const session = requireSession(req, res); if (!session) return;
      const params = url.searchParams;
      const range = parseHistoryRange(params);
      if (range.error) { sendError(res, 400, range.error); return; }
      if (Plans.planFor(session.user.plan) === 'base' && (range.start < `${Plans.baseHistoryStartMonth()}-01` || range.end > todayLocal())) {
        sendError(res, 403, 'O plano Básico permite consultar somente os últimos seis meses. Seus registros anteriores foram preservados.', { code: 'HISTORY_PERIOD_INVALID', upgrade: true }); return;
      }
      const type = params.get('type') || 'all';
      if (!['all', 'expense', 'income'].includes(type)) { sendError(res, 400, 'Tipo de movimentação inválido.'); return; }
      const category = params.get('category') || '';
      if (category && !CATEGORY_IDS.has(category)) { sendError(res, 400, 'Categoria inválida.'); return; }
      const bankId = params.get('bankId') || '';
      const q = String(params.get('q') || '').trim().slice(0, 100);
      const expenses = (type === 'income' || bankId) ? [] : DB.prepare(`SELECT * FROM expenses WHERE user_id=? AND expense_date BETWEEN ? AND ? ${category ? 'AND category=?' : ''} ${q ? "AND description LIKE ? ESCAPE '\\'" : ''} ORDER BY expense_date DESC,created_at DESC`)
        .all(session.user.id, range.start, range.end, ...(category ? [category] : []), ...(q ? [`%${q.replace(/[\\%_]/g, '\\$&')}%`] : [])).map(expenseRow);
      let incomes = [];
      if (type !== 'expense' && !category) {
        const rows = DB.prepare(`SELECT i.*,b.institution AS bank_institution,b.account_label FROM income_records i JOIN bank_accounts b ON b.id=i.bank_account_id AND b.user_id=i.user_id
          WHERE i.user_id=? AND i.received_date BETWEEN ? AND ? ${bankId ? 'AND i.bank_account_id=?' : ''} ${q ? "AND (i.source LIKE ? ESCAPE '\\' OR i.payer_name LIKE ? ESCAPE '\\' OR i.description LIKE ? ESCAPE '\\')" : ''}
          ORDER BY i.received_date DESC,i.created_at DESC`).all(session.user.id, range.start, range.end, ...(bankId ? [bankId] : []), ...(q ? [`%${q.replace(/[\\%_]/g, '\\$&')}%`, `%${q.replace(/[\\%_]/g, '\\$&')}%`, `%${q.replace(/[\\%_]/g, '\\$&')}%`] : []));
        incomes = rows.map(incomeRecordRow);
      }
      const calculations = DB.prepare('SELECT * FROM installment_calculations WHERE user_id = ? AND substr(created_at,1,10) BETWEEN ? AND ? ORDER BY created_at DESC').all(session.user.id, range.start, range.end).map(calculationRow);
      const totalOutCents = expenses.reduce((sum, row) => sum + row.amountCents, 0);
      const totalInCents = incomes.reduce((sum, row) => sum + row.amountCents, 0);
      sendJson(res, 200, { month: range.month, range: { start: range.start, end: range.end }, expenses, incomes, calculations,
        summary: { totalInCents, totalOutCents, resultCents: totalInCents - totalOutCents, movementCount: expenses.length + incomes.length },
        filters: { type, category, bankId, q } }); return;
    }
    if (pathname === '/api/banks' && method === 'GET') {
      const session = requireSession(req, res); if (!session) return;
      const banks = DB.prepare('SELECT * FROM bank_accounts WHERE user_id=? ORDER BY institution COLLATE NOCASE,account_label COLLATE NOCASE').all(session.user.id).map(bankAccountRow);
      sendJson(res, 200, { banks }); return;
    }
    if (pathname === '/api/received' && method === 'GET') {
      const session = requireSession(req, res); if (!session) return;
      const month = url.searchParams.get('month') || currentMonth();
      let range; try { range = Finance.monthRange(month); } catch { sendError(res, 400, 'Mês inválido. Use AAAA-MM.'); return; }
      const bankId = url.searchParams.get('bankId') || '';
      const banks = DB.prepare('SELECT * FROM bank_accounts WHERE user_id=? ORDER BY institution COLLATE NOCASE,account_label COLLATE NOCASE').all(session.user.id).map(bankAccountRow);
      if (bankId && !banks.some((bank) => bank.id === bankId)) { sendError(res, 404, 'Conta bancária não encontrada.'); return; }
      const rows = DB.prepare(`SELECT i.*,b.institution AS bank_institution,b.account_label FROM income_records i JOIN bank_accounts b ON b.id=i.bank_account_id AND b.user_id=i.user_id
        WHERE i.user_id=? AND i.received_date BETWEEN ? AND ? ${bankId ? 'AND i.bank_account_id=?' : ''} ORDER BY i.received_date DESC,i.created_at DESC`)
        .all(session.user.id, range.start, range.end, ...(bankId ? [bankId] : []));
      const incomes = rows.map(incomeRecordRow);
      const totalCents = incomes.reduce((sum, item) => sum + item.amountCents, 0);
      const byBank = new Map();
      for (const item of incomes) { const key = item.bankAccountId; const old = byBank.get(key) || { bankAccountId: key, institution: item.bankInstitution, accountLabel: item.accountLabel, totalCents: 0, count: 0 }; old.totalCents += item.amountCents; old.count += 1; byBank.set(key, old); }
      sendJson(res, 200, { month, banks, incomes, summary: { totalCents, count: incomes.length, byBank: [...byBank.values()] } }); return;
    }
    if (pathname === '/api/received/export.pdf' || pathname === '/api/received/export.xlsx') {
      const session = requireSession(req, res); if (!session) return;
      const format = pathname.endsWith('.pdf') ? 'pdf' : 'xlsx';
      const month = url.searchParams.get('month') || currentMonth();
      let range;
      try { range = Finance.monthRange(month); } catch { sendError(res, 400, 'Mês inválido. Use AAAA-MM.'); return; }
      const bankId = url.searchParams.get('bankId') || '';
      if (bankId && !DB.prepare('SELECT id FROM bank_accounts WHERE id=? AND user_id=?').get(bankId, session.user.id)) {
        sendError(res, 404, 'Conta bancária não encontrada.'); return;
      }
      const rows = DB.prepare(`SELECT i.*, b.institution AS bank_institution, b.account_label FROM income_records i
        JOIN bank_accounts b ON b.id=i.bank_account_id AND b.user_id=i.user_id
        WHERE i.user_id=? AND i.received_date BETWEEN ? AND ? ${bankId ? 'AND i.bank_account_id=?' : ''}
        ORDER BY i.received_date DESC, i.created_at DESC`)
        .all(session.user.id, range.start, range.end, ...(bankId ? [bankId] : []));
      if (!rows.length) { sendError(res, 404, 'Não existem recebimentos registrados no período selecionado para exportação.'); return; }
      const movements = rows.map(row => ({
        kind: 'Entrada', description: row.source, date: row.received_date,
        categoryLabel: `${row.bank_institution} · ${row.account_label}`,
        counterparty: row.payer_name, details: row.description || '', amount_cents: row.amount_cents
      }));
      const total = rows.reduce((sum, row) => sum + Number(row.amount_cents), 0);
      const summary = { totalInCents: total, totalOutCents: 0, resultCents: total, movementCount: rows.length };
      const period = `${month}${bankId ? ` · ${rows[0]?.bank_institution || 'Conta selecionada'}` : ''}`;
      let file;
      try {
        const options = { title: 'Recebimentos', sheetName: 'Recebimentos' };
        file = format === 'pdf' ? createFinancialHistoryPdf(movements, summary, period, new Date(), options)
          : createFinancialHistoryXlsx(movements, summary, period, new Date(), options);
      } catch { sendError(res, 500, 'Falha ao gerar a exportação de recebimentos.'); return; }
      // Não há uma cota de exportação de Recebidos definida pelos planos.
      // Não reservar ou consumir cotas de Despesas/Histórico/Conta.
      sendExportBuffer(res, file, {
        'Content-Type': format === 'pdf' ? 'application/pdf' : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'Content-Disposition': `attachment; filename="ovbeck_recebidos_${month}.${format}"`
      });
      return;
    }
    if (pathname === '/api/export.json') {
      sendError(res, 410, 'A exportação completa agora está disponível em PDF e Excel na seção Conta e privacidade.'); return;
    }
    if (pathname === '/api/export.pdf' || pathname === '/api/export.xlsx') {
      const session = requireSession(req, res); if (!session) return;
      const plan = Plans.planFor(session.user.plan);
      const format = pathname.endsWith('.pdf') ? 'pdf' : 'xlsx';
      const filters = expenseFilters(session.user.id, url.searchParams);
      if (filters.error) { sendError(res, 400, filters.error); return; }
      const rows = DB.prepare(`SELECT * FROM expenses WHERE ${filters.clause} ORDER BY ${filters.order}`).all(...filters.values);
      if (!rows.length) { sendError(res, 404, 'Não há despesas neste filtro para exportar.'); return; }
      const categoryNames = new Map(CATEGORIES.map((category) => [category.id, category.label]));
      const paymentNames = { nao_informado: 'Não informado', pix: 'Pix', dinheiro: 'Dinheiro', debito: 'Débito', credito: 'Crédito', boleto: 'Boleto', transferencia: 'Transferência', outro: 'Outro' };
      const mapped = rows.map((row) => ({ ...row, categoryLabel: categoryNames.get(row.category) || row.category, paymentMethodLabel: paymentNames[row.payment_method] || row.payment_method }));
      const period = url.searchParams.get('month') || 'Todas as despesas filtradas';
      let file;
      try { file = format === 'pdf' ? createPdf(mapped, period, new Date(), { premium: plan === 'premium' }) : createXlsx(mapped, period, new Date(), { premium: plan === 'premium' }); }
      catch { sendError(res, 500, 'Falha ao gerar o arquivo. Nenhuma cota foi consumida.'); return; }
      const reservation = reserveExportDownload(session.user.id, plan, 'expenses', format);
      if (!reservation.allowed) { sendError(res, 403, 'Limite mensal de exportação de despesas atingido neste formato.', { code: 'EXPORT_LIMIT_REACHED', upgrade: true, module: 'expenses', format, limit: reservation.limit, used: reservation.used }); return; }
      sendExportBuffer(res, file, {
        'Content-Type': format === 'pdf' ? 'application/pdf' : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'Content-Disposition': `attachment; filename="ovbeck_despesas_${currentMonth()}.${format}"`
      }, reservation); return;
    }
    if (pathname === '/api/account/export.pdf' || pathname === '/api/account/export.xlsx') {
      const session = requireSession(req, res); if (!session) return;
      const plan = Plans.planFor(session.user.plan);
      const format = pathname.endsWith('.pdf') ? 'pdf' : 'xlsx';
      const userRow = DB.prepare('SELECT id, full_name, email, plan, plan_status, plan_started_at, plan_expires_at, hide_expiry_notice, monthly_income_cents, monthly_budget_cents, created_at FROM users WHERE id = ?').get(session.user.id);
      const rows = DB.prepare('SELECT * FROM expenses WHERE user_id = ? ORDER BY expense_date DESC, created_at DESC').all(session.user.id);
      const categoryNames = new Map(CATEGORIES.map((category) => [category.id, category.label]));
      const paymentNames = { nao_informado: 'Não informado', pix: 'Pix', dinheiro: 'Dinheiro', debito: 'Débito', credito: 'Crédito', boleto: 'Boleto', transferencia: 'Transferência', outro: 'Outro' };
      const expenses = rows.map((row) => ({ ...row, categoryLabel: categoryNames.get(row.category) || 'Outros', paymentMethodLabel: paymentNames[row.payment_method] || row.payment_method }));
      const recurrences = DB.prepare('SELECT id, description, amount_cents, category, frequency, payment_method, notes, next_date, active, created_at, updated_at FROM recurrence_rules WHERE user_id = ? ORDER BY created_at DESC').all(session.user.id);
      const calculations = DB.prepare('SELECT * FROM installment_calculations WHERE user_id = ? ORDER BY created_at DESC').all(session.user.id);
      const incomeRecords = DB.prepare(`SELECT i.*, b.institution AS bank_institution, b.account_label FROM income_records i
        JOIN bank_accounts b ON b.id=i.bank_account_id AND b.user_id=i.user_id
        WHERE i.user_id=? ORDER BY i.received_date DESC,i.created_at DESC`).all(session.user.id);
      if (!expenses.length && !recurrences.length && !calculations.length && !incomeRecords.length) {
        sendError(res, 404, 'Não existem registros financeiros nesta conta para exportação.'); return;
      }
      const generatedAt = new Date();
      let file;
      try {
        file = format === 'pdf'
          ? createAccountPdf(userRow, expenses, recurrences, calculations, generatedAt, incomeRecords)
          : createAccountXlsx(userRow, expenses, recurrences, calculations, generatedAt, incomeRecords);
      } catch (error) {
        sendError(res, 500, 'Não foi possível gerar a exportação completa. Nenhuma cota foi consumida.'); return;
      }
      const reservation = reserveExportDownload(session.user.id, plan, 'account', format);
      if (!reservation.allowed) {
        sendError(res, 403, `Você utilizou os ${reservation.limit} downloads em ${format === 'pdf' ? 'PDF' : 'Excel'} disponíveis no plano Base para a exportação completa da conta. O Premium oferece downloads ilimitados.`, {
          code: 'EXPORT_LIMIT_REACHED', upgrade: true, plan, module: 'account', format,
          used: reservation.used, limit: reservation.limit
        }); return;
      }
      const stamp = `${todayLocal().slice(0, 7)}`;
      sendExportBuffer(res, file, {
        'Content-Type': format === 'pdf' ? 'application/pdf' : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'Content-Disposition': `attachment; filename="ovbeck_conta_${stamp}.${format}"`
      }, reservation);
      return;
    }
    if (['/api/history/export.pdf', '/api/history/export.xlsx'].includes(pathname)) {
      const session = requireSession(req, res); if (!session) return;
      const plan = Plans.planFor(session.user.plan);
      const module = 'history';
      const format = pathname.endsWith('.pdf') ? 'pdf' : 'xlsx';
      const type = url.searchParams.get('type') || 'all';
      if (!['all', 'expense', 'income'].includes(type)) { sendError(res, 400, 'Tipo de movimentação inválido.'); return; }
      let selectedMonth = url.searchParams.get('month') || '';
      if (url.searchParams.get('all') === '1') selectedMonth = '';
      else if (!selectedMonth) selectedMonth = currentMonth();
      if (selectedMonth && !Plans.canViewHistoryMonth(plan, selectedMonth)) {
        sendError(res, 403, 'O mês informado não está disponível no seu plano.', { code: 'HISTORY_PERIOD_INVALID', upgrade: plan === 'base' }); return;
      }
      let range = null;
      let period = 'Todo o histórico';
      if (selectedMonth) {
        try { range = Finance.monthRange(selectedMonth); } catch { sendError(res, 400, 'Mês inválido. Use AAAA-MM.'); return; }
        period = new Intl.DateTimeFormat('pt-BR', { month: 'long', year: 'numeric', timeZone: 'UTC' }).format(new Date(`${selectedMonth}-15T12:00:00Z`));
      } else if (plan === 'base') {
        range = { start: `${Plans.baseHistoryStartMonth()}-01`, end: todayLocal() };
        period = 'Últimos seis meses';
      }
      const category = url.searchParams.get('category') || '';
      const status = url.searchParams.get('status') || '';
      const bankId = url.searchParams.get('bankId') || '';
      const q = String(url.searchParams.get('q') || '').trim().slice(0, 100);
      if (category && !CATEGORY_IDS.has(category)) { sendError(res, 400, 'Categoria inválida.'); return; }
      if (status && !STATUSES.has(status)) { sendError(res, 400, 'Situação inválida.'); return; }
      if (bankId && !DB.prepare('SELECT id FROM bank_accounts WHERE id=? AND user_id=?').get(bankId, session.user.id)) { sendError(res, 404, 'Conta bancária não encontrada.'); return; }
      const expenseWhere = ['e.user_id = ?']; const expenseValues = [session.user.id];
      if (range) { expenseWhere.push('e.expense_date BETWEEN ? AND ?'); expenseValues.push(range.start, range.end); }
      if (category) { expenseWhere.push('e.category = ?'); expenseValues.push(category); }
      if (status) { expenseWhere.push('e.status = ?'); expenseValues.push(status); }
      if (q) { expenseWhere.push("e.description LIKE ? ESCAPE '\\'"); expenseValues.push(`%${q.replace(/[\\%_]/g, '\\$&')}%`); }
      const expenses = type === 'income' ? [] : DB.prepare(`SELECT e.description,e.amount_cents,e.category,e.expense_date,e.due_date,e.status,e.payment_method,e.notes,e.created_at
        FROM expenses e WHERE ${expenseWhere.join(' AND ')} ORDER BY e.expense_date DESC,e.created_at DESC`).all(...expenseValues);
      const incomeWhere = ['i.user_id = ?']; const incomeValues = [session.user.id];
      if (range) { incomeWhere.push('i.received_date BETWEEN ? AND ?'); incomeValues.push(range.start, range.end); }
      if (bankId) { incomeWhere.push('i.bank_account_id = ?'); incomeValues.push(bankId); }
      if (q) { incomeWhere.push("(i.source LIKE ? ESCAPE '\\' OR i.payer_name LIKE ? ESCAPE '\\' OR i.description LIKE ? ESCAPE '\\')"); const pattern = `%${q.replace(/[\\%_]/g, '\\$&')}%`; incomeValues.push(pattern, pattern, pattern); }
      // Categoria e situação são filtros próprios de despesas e não devem incluir entradas sem correspondência.
      const incomes = type === 'expense' || category || status ? [] : DB.prepare(`SELECT i.received_date,i.amount_cents,i.source,i.payer_name,i.description,i.created_at,b.institution AS bank_institution,b.account_label
        FROM income_records i JOIN bank_accounts b ON b.id=i.bank_account_id AND b.user_id=i.user_id
        WHERE ${incomeWhere.join(' AND ')} ORDER BY i.received_date DESC,i.created_at DESC`).all(...incomeValues);
      if (!expenses.length && !incomes.length) { sendError(res, 404, 'Não há movimentações no período selecionado para exportar. Ajuste os filtros ou registre uma movimentação.'); return; }
      const categoryNames = new Map(CATEGORIES.map((item) => [item.id, item.label]));
      const paymentNames = { nao_informado: 'Não informado', pix: 'Pix', dinheiro: 'Dinheiro', debito: 'Débito', credito: 'Crédito', boleto: 'Boleto', transferencia: 'Transferência', outro: 'Outro' };
      const movements = [
        ...expenses.map((row) => ({ kind: 'Saída', description: row.description, date: row.expense_date, categoryLabel: categoryNames.get(row.category) || 'Outros', counterparty: paymentNames[row.payment_method] || row.payment_method || '', details: [row.status === 'paid' ? 'Concluída' : 'Pendente', row.due_date ? `Vencimento ${row.due_date}` : '', row.notes || ''].filter(Boolean).join(' · '), amount_cents: row.amount_cents, created_at: row.created_at })),
        ...incomes.map((row) => ({ kind: 'Entrada', description: row.description || row.source, date: row.received_date, categoryLabel: `${row.bank_institution} · ${row.account_label}`, counterparty: `${row.source} · ${row.payer_name}`, details: row.description || '', amount_cents: row.amount_cents, created_at: row.created_at }))
      ].sort((a, b) => `${b.date}${b.created_at}`.localeCompare(`${a.date}${a.created_at}`));
      const summary = {
        totalInCents: incomes.reduce((sum, row) => sum + Number(row.amount_cents || 0), 0),
        totalOutCents: expenses.reduce((sum, row) => sum + Number(row.amount_cents || 0), 0),
        movementCount: movements.length
      };
      summary.resultCents = summary.totalInCents - summary.totalOutCents;
      const periodParts = [period];
      if (type !== 'all') periodParts.push(type === 'expense' ? 'Somente despesas' : 'Somente recebidos');
      if (category) periodParts.push(`Categoria: ${categoryNames.get(category) || 'Outros'}`);
      if (status) periodParts.push(`Situação: ${status === 'paid' ? 'Concluída' : 'Pendente'}`);
      if (bankId) { const bank = DB.prepare('SELECT institution,account_label FROM bank_accounts WHERE id=? AND user_id=?').get(bankId, session.user.id); if (bank) periodParts.push(`Conta: ${bank.institution} · ${bank.account_label}`); }
      if (q) periodParts.push(`Busca: ${q}`);
      period = periodParts.join(' | ').slice(0, 180);
      let file;
      try { file = format === 'pdf' ? createFinancialHistoryPdf(movements, summary, period, new Date()) : createFinancialHistoryXlsx(movements, summary, period, new Date()); }
      catch { sendError(res, 500, 'Não foi possível gerar o arquivo. Nenhuma cota foi consumida.'); return; }
      const reservation = reserveExportDownload(session.user.id, plan, module, format);
      if (!reservation.allowed) {
        sendError(res, 403, `Você utilizou os ${reservation.limit} downloads de ${format === 'pdf' ? 'PDF' : 'Excel'} disponíveis no plano Base para o Histórico. O Premium oferece downloads ilimitados.`, {
          code: 'EXPORT_LIMIT_REACHED', upgrade: true, plan, module, format, used: reservation.used, limit: reservation.limit
        }); return;
      }
      const rangeLabel = selectedMonth || 'historico_completo';
      sendExportBuffer(res, file, {
        'Content-Type': format === 'pdf' ? 'application/pdf' : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'Content-Disposition': `attachment; filename="historico_ovbeck_${rangeLabel}.${format}"`
      }, reservation);
      return;
    }
    if (pathname === '/api/auth/logout') { sendError(res, 405, 'Use POST para encerrar a sessão.'); return; }
    if (pathname.startsWith('/api/')) { sendError(res, 404, 'Endpoint da API não encontrado.'); return; }
    if (pathname === '/admin' || pathname === '/admin/') {
      const adminSession = adminSessionForRequest(req);
      if (!adminSession) { res.writeHead(302, { Location: '/', 'Cache-Control': 'no-store' }); res.end(); return; }
    }
    if (method === 'HEAD') { const file = STATIC_FILES.get(pathname); if (!file) { res.writeHead(404); res.end(); return; } serveStatic(pathname, req, res); return; }
    serveStatic(pathname, req, res); return;
  }

  const session = sessionForRequest(req);
  if (!checkMutationProtection(req, res, session)) return;

  if (pathname === '/api/profile/photo' && method === 'POST') {
    const body = await readJson(req, 56 * 1024 * 1024);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['dataBase64', 'cropX', 'cropY']) ||
        typeof body.dataBase64 !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(body.dataBase64) ||
        (body.cropX !== undefined && (!Number.isFinite(body.cropX) || body.cropX < 0 || body.cropX > 1)) ||
        (body.cropY !== undefined && (!Number.isFinite(body.cropY) || body.cropY < 0 || body.cropY > 1))) {
      sendError(res, 400, 'Envie um arquivo de imagem válido e um enquadramento entre 0 e 100%.'); return;
    }
    const inputImage = Buffer.from(body.dataBase64, 'base64');
    const maxPhotoBytes = 40 * 1024 * 1024;
    if (!inputImage.length || inputImage.length > maxPhotoBytes) {
      sendError(res, 413, 'O arquivo ultrapassa o limite técnico de 40 MB. Reduza o arquivo e tente novamente.'); return;
    }
    let normalizedPhoto;
    try {
      const imageOptions = { animated: true, limitInputPixels: 120_000_000, sequentialRead: true, failOn: 'warning' };
      const metadata = await sharp(inputImage, imageOptions).metadata();
      const supportedStaticFormats = new Set(['jpeg', 'png', 'webp', 'tiff', 'heif']);
      if (metadata.format === 'gif' || Number(metadata.pages || 1) > 1 || (metadata.pageHeight && metadata.height > metadata.pageHeight)) {
        sendError(res, 415, 'GIFs, APNGs, WebP animados e outras imagens com múltiplos quadros não são aceitos. Selecione uma imagem estática.'); return;
      }
      if (!supportedStaticFormats.has(metadata.format)) {
        sendError(res, 415, 'Formato não suportado pelo processador de imagens desta instalação. Use JPEG, PNG, WebP, TIFF, AVIF ou HEIC/HEIF. BMP deve ser convertido pelo navegador para JPEG.'); return;
      }
      if (!metadata.width || !metadata.height || metadata.width < 1 || metadata.height < 1 || metadata.width * metadata.height > 120_000_000) {
        sendError(res, 413, 'A resolução excede o limite seguro de processamento (120 megapixels). Reduza a resolução e tente novamente.'); return;
      }
      const swapsDimensions = [5, 6, 7, 8].includes(Number(metadata.orientation));
      const width = swapsDimensions ? metadata.height : metadata.width;
      const height = swapsDimensions ? metadata.width : metadata.height;
      const cropSize = Math.min(width, height);
      const cropX = Number.isFinite(body.cropX) ? body.cropX : 0.5;
      const cropY = Number.isFinite(body.cropY) ? body.cropY : 0.5;
      const left = Math.max(0, Math.min(width - cropSize, Math.round((width - cropSize) * cropX)));
      const top = Math.max(0, Math.min(height - cropSize, Math.round((height - cropSize) * cropY)));
      normalizedPhoto = await sharp(inputImage, imageOptions)
        .rotate()
        .extract({ left, top, width: cropSize, height: cropSize })
        .resize(512, 512, { fit: 'fill', kernel: 'lanczos3' })
        .flatten({ background: '#15251F' })
        .jpeg({ quality: 88, mozjpeg: true })
        .toBuffer();
      if (!normalizedPhoto.length || normalizedPhoto.length > 1024 * 1024) {
        sendError(res, 422, 'Não foi possível gerar uma versão otimizada e segura da imagem. Escolha outra foto.'); return;
      }
    } catch (error) {
      const reason = String(error?.message || '').toLowerCase();
      if (reason.includes('pixel limit') || reason.includes('exceeds')) sendError(res, 413, 'A imagem ultrapassa a capacidade segura de processamento desta instalação.');
      else sendError(res, 400, 'Não foi possível decodificar o arquivo como imagem estática. Verifique se o arquivo está íntegro e tente novamente.');
      return;
    }
    const stamp = nowISO();
    DB.prepare(`UPDATE users SET profile_photo=?, profile_photo_mime='image/jpeg', profile_photo_updated_at=?, updated_at=? WHERE id=? AND account_status='active'`)
      .run(normalizedPhoto, stamp, stamp, session.user.id);
    const updated = DB.prepare('SELECT * FROM users WHERE id=?').get(session.user.id);
    sendJson(res, 200, { user: safePublicUser(updated), message: 'Foto de perfil atualizada e otimizada.' }); return;
  }
  if (pathname === '/api/profile/photo' && method === 'DELETE') {
    const stamp = nowISO();
    const result = DB.prepare(`UPDATE users SET profile_photo=NULL, profile_photo_mime=NULL, profile_photo_updated_at=NULL, updated_at=? WHERE id=? AND account_status='active'`)
      .run(stamp, session.user.id);
    if (!result.changes) { sendError(res, 404, 'Conta não encontrada.'); return; }
    const updated = DB.prepare('SELECT * FROM users WHERE id=?').get(session.user.id);
    sendJson(res, 200, { user: safePublicUser(updated), message: 'Foto de perfil removida.' }); return;
  }

  if (pathname === '/api/account/theme' && (method === 'PUT' || method === 'POST')) {
    const current = DB.prepare("SELECT plan, theme_accent, theme_surfaces, account_status FROM users WHERE id=?").get(session.user.id);
    if (!current || current.account_status !== 'active') { sendError(res, 404, 'Conta não encontrada.'); return; }
    if (Plans.planFor(current.plan) !== 'premium') { sendError(res, 403, 'A personalização visual é um benefício exclusivo do Premium.', { code: 'PREMIUM_REQUIRED' }); return; }
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['accent', 'surfaces']) || (body.accent === undefined && body.surfaces === undefined)) {
      sendError(res, 400, 'Informe uma cor para os elementos e/ou uma paleta de superfícies.'); return;
    }
    let accent = normalizeHexColorServer(body.accent ?? current.theme_accent) || normalizeHexColorServer(current.theme_accent) || '#4BD3A2';
    let surfaces = readThemeSurfaces(current.theme_surfaces);
    if (body.surfaces !== undefined) {
      if (!isPlainObject(body.surfaces) || !hasOnlyKeys(body.surfaces, THEME_SURFACE_KEYS)) { sendError(res, 400, 'A paleta de fundos contém áreas desconhecidas.'); return; }
      const normalized = { ...surfaces };
      for (const key of THEME_SURFACE_KEYS) {
        if (body.surfaces[key] !== undefined) {
          const color = normalizeHexColorServer(body.surfaces[key]);
          if (!color) { sendError(res, 400, `O código de cor da área ${key} é inválido. Use #RGB ou #RRGGBB.`); return; }
          normalized[key] = color;
        }
      }
      surfaces = normalized;
    }
    if (body.accent !== undefined && !normalizeHexColorServer(body.accent)) { sendError(res, 400, 'O código de cor dos elementos é inválido. Use #RGB ou #RRGGBB.'); return; }
    DB.prepare("UPDATE users SET theme_accent=?, theme_surfaces=?, updated_at=? WHERE id=? AND plan='premium'").run(accent, JSON.stringify(surfaces), nowISO(), session.user.id);
    const updated = safePublicUser(DB.prepare('SELECT * FROM users WHERE id=?').get(session.user.id));
    sendJson(res, 200, { user: updated, accent, surfaces, message: 'Personalização salva com sucesso.' }); return;
  }

  if (pathname === '/api/account/theme/reset' && method === 'POST') {
    const current = DB.prepare("SELECT plan, account_status, theme_accent, theme_surfaces FROM users WHERE id=?").get(session.user.id);
    if (!current || current.account_status !== 'active') { sendError(res, 404, 'Conta não encontrada.'); return; }
    if (Plans.planFor(current.plan) !== 'premium') { sendError(res, 403, 'A personalização visual é um benefício exclusivo do Premium.', { code: 'PREMIUM_REQUIRED' }); return; }
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['target']) || (body.target !== undefined && !['elements', 'surfaces', 'all'].includes(body.target))) { sendError(res, 400, 'Selecione uma área válida para restaurar.'); return; }
    const target = body.target || 'all';
    const accent = target === 'surfaces' ? (normalizeHexColorServer(current.theme_accent) || '#4BD3A2') : '#4BD3A2';
    const surfaces = target === 'elements' ? readThemeSurfaces(current.theme_surfaces) : {}; 
    DB.prepare("UPDATE users SET theme_accent=?, theme_surfaces=?, updated_at=? WHERE id=? AND plan='premium'").run(accent, JSON.stringify(surfaces), nowISO(), session.user.id);
    const updated = safePublicUser(DB.prepare('SELECT * FROM users WHERE id=?').get(session.user.id));
    sendJson(res, 200, { user: updated, accent, surfaces, target, message: target === 'elements' ? 'Elementos e detalhes restaurados.' : target === 'surfaces' ? 'Fundos e superfícies restaurados.' : 'Toda a personalização foi restaurada.' }); return;
  }

  if (pathname === '/api/accounts/link' && method === 'POST') {
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['email', 'password', 'secondStepCode']) || !validateText(body.email, 254, true) || !isValidEmailAddress(body.email) || !validateText(body.password, 128, true)) {
      sendError(res, 400, 'Informe o e-mail e a senha da conta que deseja vincular.'); return;
    }
    const membership = DB.prepare('SELECT group_id FROM account_link_members WHERE user_id = ?').get(session.user.id);
    let groupId = membership?.group_id || null;
    if (groupId && !DB.prepare('SELECT id FROM account_link_groups WHERE id = ?').get(groupId)) groupId = null;
    if (!groupId && Plans.planFor(session.user.plan) === 'premium') groupId = ensureAccountLinkGroup(session.user.id);
    if (!groupId) {
      sendError(res, 403, 'A troca de contas está disponível no Premium. O plano Base permite utilizar apenas uma conta.', { code: 'ACCOUNT_LINK_PREMIUM_REQUIRED', upgrade: true }); return;
    }
    const groupOwner = DB.prepare(`SELECT owner.plan AS plan FROM account_link_groups g JOIN users owner ON owner.id = g.owner_user_id WHERE g.id = ?`).get(groupId);
    if (!groupOwner || Plans.planFor(groupOwner.plan) !== 'premium') {
      sendError(res, 403, 'O grupo de contas precisa ter o plano Premium ativo para vincular outras contas.', { code: 'ACCOUNT_LINK_PREMIUM_REQUIRED', upgrade: true }); return;
    }
    const target = DB.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE').get(normalizeEmail(body.email));
    if (!target || target.account_status !== 'active' || !(await verifyPassword(body.password, target.password_salt, target.password_hash))) {
      sendError(res, 403, 'Não foi possível autenticar essa conta. Confira o e-mail e a senha.'); return;
    }
    if (target.demo_two_factor_enabled === 1) {
      // Vincular requer a mesma etapa adicional demonstrativa do login; nunca
      // aceitar um código arbitrário fora do ambiente explicitamente permitido.
      if (!DEMO_SECOND_STEP) { sendError(res, 403, 'Esta conta exige verificação adicional, indisponível neste ambiente.', { code: 'SECOND_STEP_NOT_CONFIGURED' }); return; }
      if (typeof body.secondStepCode !== 'string' || !/^\d{6}$/.test(body.secondStepCode)) {
        sendError(res, 428, 'Esta conta exige uma verificação adicional demonstrativa de seis dígitos. Nenhum e-mail será enviado.', { code: 'SECOND_STEP_REQUIRED' }); return;
      }
    }
    if (target.id === session.user.id) { sendError(res, 409, 'Esta já é a conta ativa.'); return; }
    DB.exec('BEGIN IMMEDIATE');
    try {
      const owner = DB.prepare(`SELECT g.owner_user_id, owner.plan AS plan FROM account_link_groups g JOIN users owner ON owner.id = g.owner_user_id WHERE g.id = ?`).get(groupId);
      if (!owner || Plans.planFor(owner.plan) !== 'premium') {
        DB.exec('ROLLBACK'); sendError(res, 403, 'O plano Premium do grupo não está ativo para novas contas.', { code: 'ACCOUNT_LINK_PREMIUM_REQUIRED' }); return;
      }

      const existing = DB.prepare('SELECT group_id FROM account_link_members WHERE user_id = ?').get(target.id);
      if (existing && existing.group_id === groupId) {
        DB.exec('ROLLBACK'); sendError(res, 409, 'Esta conta já está vinculada a este grupo.'); return;
      }
      if (existing) {
        const previousGroup = DB.prepare('SELECT id, owner_user_id FROM account_link_groups WHERE id = ?').get(existing.group_id);
        if (!previousGroup) {
          // Relacionamento órfão: a FK deveria impedir isso, mas versões antigas ou
          // importações externas podem ter deixado a linha sem o grupo correspondente.
          DB.prepare('DELETE FROM account_link_members WHERE user_id = ? AND group_id = ?').run(target.id, existing.group_id);
        } else {
          const previousMembers = DB.prepare('SELECT user_id FROM account_link_members WHERE group_id = ?').all(existing.group_id);
          const isPersonalSingleton = previousGroup.owner_user_id === target.id
            && previousMembers.length === 1 && previousMembers[0].user_id === target.id;
          if (!isPersonalSingleton) {
            DB.exec('ROLLBACK');
            sendError(res, 409, 'Esta conta já está vinculada a outro grupo de contas. Desvincule-a do grupo atual antes de adicioná-la a este.'); return;
          }
          // Grupos singleton criados automaticamente por versões anteriores eram
          // apenas marcadores pessoais, não vínculos com outra pessoa. Removemos
          // esse marcador na mesma transação da nova vinculação.
          DB.prepare('DELETE FROM account_link_groups WHERE id = ? AND owner_user_id = ?').run(existing.group_id, target.id);
        }
      } else {
        // Limpa apenas grupos realmente vazios do alvo. Se houver outros membros,
        // o alvo administra um grupo existente e não deve ser movido silenciosamente.
        const ownedGroup = DB.prepare('SELECT id FROM account_link_groups WHERE owner_user_id = ?').get(target.id);
        if (ownedGroup) {
          const ownedMembers = DB.prepare('SELECT user_id FROM account_link_members WHERE group_id = ?').all(ownedGroup.id);
          if (ownedMembers.length > 0) {
            DB.exec('ROLLBACK');
            sendError(res, 409, 'Esta conta administra outro grupo de contas e não pode ser adicionada a um grupo diferente enquanto houver membros vinculados.'); return;
          }
          DB.prepare('DELETE FROM account_link_groups WHERE id = ?').run(ownedGroup.id);
        }
      }

      const count = Number(DB.prepare('SELECT COUNT(*) AS total FROM account_link_members WHERE group_id = ?').get(groupId).total);
      if (count >= Plans.LINKED_ACCOUNTS_PREMIUM) {
        DB.exec('ROLLBACK'); sendError(res, 403, 'O Premium permite até três perfis no seletor de contas.', { code: 'ACCOUNT_LIMIT_REACHED', upgrade: false, used: count, limit: Plans.LINKED_ACCOUNTS_PREMIUM }); return;
      }
      DB.prepare('INSERT INTO account_link_members(group_id, user_id, linked_at) VALUES (?, ?, ?)').run(groupId, target.id, nowISO());
      DB.exec('COMMIT');
    } catch (error) {
      try { DB.exec('ROLLBACK'); } catch { /* transaction may already be finished */ }
      if (String(error.code || '').includes('SQLITE_CONSTRAINT')) { sendError(res, 409, 'A conta já está vinculada a outro grupo.'); return; }
      throw error;
    }
    sendJson(res, 201, { ok: true, ...linkedAccountsFor(DB.prepare('SELECT * FROM users WHERE id = ?').get(session.user.id)) }); return;
  }
  if (pathname === '/api/accounts/switch' && method === 'POST') {
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['userId']) || typeof body.userId !== 'string' || !/^[0-9a-f-]{36}$/i.test(body.userId)) {
      sendError(res, 400, 'Selecione uma conta válida.'); return;
    }
    if (body.userId === session.user.id) {
      sendJson(res, 200, { authenticated: true, user: session.publicUser, csrfToken: session.csrfToken, unchanged: true }); return;
    }
    const currentMembership = DB.prepare('SELECT group_id FROM account_link_members WHERE user_id = ?').get(session.user.id);
    const targetMembership = DB.prepare('SELECT group_id FROM account_link_members WHERE user_id = ?').get(body.userId);
    if (!currentMembership || !targetMembership || currentMembership.group_id !== targetMembership.group_id) {
      sendError(res, 403, 'Essa conta não está vinculada ao seletor da conta ativa. Autentique-a antes de vincular.'); return;
    }
    const switchGroup = DB.prepare(`SELECT owner.plan AS owner_plan FROM account_link_groups g JOIN users owner ON owner.id = g.owner_user_id WHERE g.id = ?`).get(currentMembership.group_id);
    if (!switchGroup || Plans.planFor(switchGroup.owner_plan) !== 'premium') {
      sendError(res, 403, 'A troca entre contas está disponível enquanto o grupo estiver no Premium. Os vínculos foram preservados, mas a troca está suspensa no plano Base.', { code: 'ACCOUNT_LINK_PREMIUM_REQUIRED', upgrade: true }); return;
    }
    const targetUser = DB.prepare('SELECT * FROM users WHERE id = ?').get(body.userId);
    if (!targetUser) { sendError(res, 404, 'A conta selecionada não foi encontrada.'); return; }
    DB.exec('BEGIN IMMEDIATE');
    let newSession;
    try {
      DB.prepare('DELETE FROM sessions WHERE token_hash = ?').run(session.tokenHash);
      newSession = createSession(targetUser.id);
      DB.exec('COMMIT');
    } catch (error) {
      try { DB.exec('ROLLBACK'); } catch { /* transaction may already be finished */ }
      throw error;
    }
    sendJson(res, 200, { authenticated: true, user: safePublicUser(targetUser), csrfToken: newSession.csrfToken, switched: true }, { 'Set-Cookie': secureCookie(newSession.token, Math.floor(SESSION_MS / 1000)) }); return;
  }
  if (pathname === '/api/auth/logout' && method === 'POST') {
    DB.prepare('DELETE FROM sessions WHERE token_hash = ?').run(session.tokenHash);
    sendJson(res, 200, { ok: true }, { 'Set-Cookie': clearCookie() }); return;
  }
  if (pathname === '/api/account/expiry-notice' && method === 'PATCH') {
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['hide']) || typeof body.hide !== 'boolean') { sendError(res, 400, 'A preferência do aviso deve ser verdadeira ou falsa.'); return; }
    DB.prepare('UPDATE users SET hide_expiry_notice = ?, updated_at = ? WHERE id = ?').run(body.hide ? 1 : 0, nowISO(), session.user.id);
    sendJson(res, 200, safePublicUser(DB.prepare('SELECT * FROM users WHERE id = ?').get(session.user.id))); return;
  }

  if (pathname === '/api/account/premium/checkout' && method === 'POST') {
    if (!checkMutationProtection(req, res, session)) return;
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['trialConsent']) || body.trialConsent !== true) {
      sendError(res, 400, 'Confirme expressamente as condições da assinatura Premium antes de continuar.'); return;
    }
    try {
      const user = DB.prepare("SELECT * FROM users WHERE id=? AND account_status='active'").get(session.user.id);
      const checkout = await createPremiumCheckoutForUser(user, { trialConsent: true });
      sendJson(res, 200, { checkoutUrl: checkout.checkoutUrl, trialDays: checkout.trialDays, provider: 'mercadopago', subscriptionId: checkout.subscriptionId });
    } catch (error) {
      sendError(res, error.status || 502, error.message || 'Não foi possível iniciar a contratação Premium.', { code: error.code || 'PREMIUM_CHECKOUT_FAILED' });
    }
    return;
  }

  if (pathname === '/api/account/premium/local-upgrade' && method === 'POST') {
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['billing'])) {
      sendError(res, 400, 'Os dados da etapa de adesão são inválidos.'); return;
    }
    if (!LOCAL_PREMIUM_ACCESS) {
      sendError(res, 409, 'A adesão local ao Premium não está habilitada nesta instalação. Nenhuma cobrança foi realizada.', { code: 'LOCAL_PREMIUM_ACCESS_DISABLED' }); return;
    }
    const current = DB.prepare("SELECT * FROM users WHERE id=? AND account_status='active'").get(session.user.id);
    if (!current) { sendError(res, 404, 'Conta ativa não encontrada.'); return; }
    if (Plans.planFor(current.plan) === 'premium') { sendError(res, 409, 'Esta conta já utiliza o plano Premium.'); return; }
    const billingError = validateCheckoutBilling(body.billing, current.email);
    if (billingError) { sendError(res, 400, billingError); return; }
    const stamp = nowISO();
    DB.exec('BEGIN IMMEDIATE');
    try {
      const latest = DB.prepare("SELECT plan, account_status FROM users WHERE id=?").get(session.user.id);
      if (!latest || latest.account_status !== 'active' || latest.plan === 'premium') {
        DB.exec('ROLLBACK'); sendError(res, 409, 'A situação da conta mudou. Atualize a página e confira seu plano.'); return;
      }
      DB.prepare(`UPDATE users SET full_name=?, billing_full_name=?, billing_phone=?, billing_cep=?, billing_street=?, billing_number=?,
        billing_district=?, billing_city=?, billing_state=?, billing_complement=?, plan='premium', plan_status='legacy',
        premium_subscription_status='local_access', plan_started_at=?, plan_expires_at=NULL, premium_trial_started_at=NULL,
        premium_trial_ends_at=NULL, premium_first_billing_at=NULL, premium_first_billing_period_ends_at=NULL,
        premium_provider_subscription_id=NULL, premium_next_payment_at=NULL, updated_at=? WHERE id=? AND account_status='active'`)
        .run(body.billing.fullName.trim(), body.billing.fullName.trim(), body.billing.phone, body.billing.cep, body.billing.street.trim(),
          body.billing.number, body.billing.district.trim(), body.billing.city.trim(), body.billing.state.trim(), body.billing.complement.trim(), stamp, stamp, session.user.id);
      DB.exec('COMMIT');
    } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
    const updated = safePublicUser(DB.prepare('SELECT * FROM users WHERE id=?').get(session.user.id));
    sendJson(res, 200, { ok: true, user: updated, message: 'Plano Premium habilitado nesta instalação local. Os dados de cartão e o CVV foram descartados; nenhuma cobrança ou assinatura foi criada.' });
    return;
  }

  if (pathname === '/api/account/plan' && method === 'PATCH') {
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['plan']) || !['base', 'premium'].includes(body.plan)) {
      sendError(res, 400, 'Selecione um plano válido.'); return;
    }
    const current = DB.prepare("SELECT * FROM users WHERE id=? AND account_status='active'").get(session.user.id);
    if (!current) { sendError(res, 404, 'Conta não encontrada.'); return; }
    if (body.plan === 'premium') {
      if (!LOCAL_PREMIUM_ACCESS) { sendError(res, 409, 'O Premium exige contratação e autorização do provedor.'); return; }
      const stamp = nowISO();
      DB.exec('BEGIN IMMEDIATE');
      try {
        DB.prepare("UPDATE users SET plan='premium', plan_status='legacy', plan_started_at=?, plan_expires_at=NULL, premium_subscription_status='local_access', premium_trial_started_at=NULL, premium_trial_ends_at=NULL, premium_first_billing_at=NULL, premium_first_billing_period_ends_at=NULL, premium_provider_subscription_id=NULL, premium_next_payment_at=NULL, updated_at=? WHERE id=? AND account_status='active'").run(stamp, stamp, session.user.id);
        DB.exec('COMMIT');
      } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
      const updated = safePublicUser(DB.prepare('SELECT * FROM users WHERE id=?').get(session.user.id));
      sendJson(res, 200, { ok: true, plan: 'premium', user: updated, message: 'Plano Premium ativado nesta instalação local. Nenhuma assinatura ou cobrança foi criada.' });
      return;
    }
    const latest = DB.prepare(`SELECT * FROM payment_subscriptions WHERE user_id=? AND status IN ('creating','pending','authorized','trialing','active','past_due') ORDER BY created_at DESC LIMIT 1`).get(session.user.id);
    if (latest?.provider_subscription_id) {
      try {
        const remote = await MercadoPago.cancelSubscription(latest.provider_subscription_id);
        if (remote?.status && !['canceled','cancelled'].includes(String(remote.status))) throw new Error('O provedor não confirmou o cancelamento.');
      } catch { sendError(res, 502, 'Não foi possível confirmar o cancelamento da assinatura no provedor. Seu plano não foi alterado.'); return; }
    }
    const stamp = nowISO();
    DB.exec('BEGIN IMMEDIATE');
    try {
      DB.prepare(`UPDATE payment_subscriptions SET status='canceled', canceled_at=COALESCE(canceled_at,?), provider_status='canceled', updated_at=?
        WHERE user_id=? AND status IN ('creating','pending','authorized','trialing','active','past_due')`).run(stamp, stamp, session.user.id);
      DB.prepare(`UPDATE users SET plan='base', plan_status='free', plan_started_at=NULL, plan_expires_at=NULL,
        premium_subscription_status=CASE WHEN premium_subscription_status='none' THEN 'none' ELSE 'canceled' END, premium_trial_started_at=NULL, premium_trial_ends_at=NULL,
        premium_first_billing_at=NULL, premium_first_billing_period_ends_at=NULL, premium_trial_cancel_requested_at=?, premium_provider_subscription_id=NULL,
        premium_next_payment_at=NULL, updated_at=? WHERE id=?`).run(latest?.provider_subscription_id ? stamp : null, stamp, session.user.id);
      DB.exec('COMMIT');
    } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
    const updated = safePublicUser(DB.prepare('SELECT * FROM users WHERE id=?').get(session.user.id));
    sendJson(res, 200, { ok: true, plan: 'base', user: updated, message: latest?.provider_subscription_id ? 'Assinatura cancelada e plano Base ativado.' : 'Plano Base ativado.' });
    return;
  }

  if (['/api/account/subscription/cancel', '/api/account/subscription/cancel-trial'].includes(pathname) && method === 'POST') {
    if (!checkMutationProtection(req, res, session)) return;
    const body = await readJson(req);
    if (!isPlainObject(body) || Object.keys(body).length !== 0) { sendError(res, 400, 'A solicitação de cancelamento é inválida.'); return; }
    const latest = DB.prepare(`SELECT * FROM payment_subscriptions WHERE user_id=? AND status IN ('creating','pending','authorized','trialing','active','past_due') ORDER BY created_at DESC LIMIT 1`).get(session.user.id);
    if (!latest?.provider_subscription_id) { sendError(res, 409, 'Não existe uma assinatura Premium ativa para cancelar.'); return; }
    try {
      const canceled = await MercadoPago.cancelSubscription(latest.provider_subscription_id);
      if (canceled?.status && !['canceled','cancelled'].includes(String(canceled.status))) throw new Error('O provedor não confirmou o cancelamento.');
      const stamp = nowISO();
      DB.exec('BEGIN IMMEDIATE');
      try {
        DB.prepare(`UPDATE payment_subscriptions SET status='canceled', cancel_requested_at=?, canceled_at=?, provider_status='canceled', updated_at=? WHERE id=?`)
          .run(stamp, stamp, stamp, latest.id);
        DB.prepare(`UPDATE users SET plan='base', plan_status='free', plan_started_at=NULL, plan_expires_at=NULL,
          premium_subscription_status='canceled', premium_trial_cancel_requested_at=?, updated_at=? WHERE id=?`)
          .run(stamp, stamp, session.user.id);
        DB.exec('COMMIT');
      } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
      const updatedUser = safePublicUser(DB.prepare('SELECT * FROM users WHERE id=?').get(session.user.id));
      sendJson(res, 200, { canceled: true, user: updatedUser, message: 'Assinatura cancelada no Mercado Pago. Novas cobranças recorrentes foram interrompidas.' });
    } catch (error) { sendError(res, 502, 'Não foi possível confirmar o cancelamento no provedor. Tente novamente.', { code: 'PAYMENT_CANCEL_FAILED' }); }
    return;
  }

  if (pathname === '/api/profile' && method === 'PATCH') {
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['monthlyIncome', 'monthlyBudget']) || typeof body.monthlyIncome !== 'string' || typeof body.monthlyBudget !== 'string' || !body.monthlyIncome.trim() || !body.monthlyBudget.trim()) { sendError(res, 400, 'Informe a renda mensal e o limite de gastos mensal.'); return; }
    const updates = {};
    for (const key of ['monthlyIncome', 'monthlyBudget']) {
      const cents = Finance.parseMoneyCents(body[key]);
      if (!Number.isSafeInteger(cents) || cents < 0 || cents > 9_000_000_000_000) { sendError(res, 400, `Informe um valor monetário válido para ${key === 'monthlyIncome' ? 'renda mensal' : 'limite de gastos mensal'}.`); return; }
      updates[key === 'monthlyIncome' ? 'monthly_income_cents' : 'monthly_budget_cents'] = cents;
    }
    // BEGIN IMMEDIATE serializa operações concorrentes; a comparação usa centavos inteiros
    // e o estado persistido atual, não uma lista histórica nem valores brutos da interface.
    let unchanged = false;
    let savedUser;
    DB.exec('BEGIN IMMEDIATE');
    try {
      const current = DB.prepare('SELECT * FROM users WHERE id = ?').get(session.user.id);
      if (!current) {
        DB.exec('ROLLBACK');
        sendError(res, 404, 'Conta não encontrada.');
        return;
      }
      unchanged = Number(current.monthly_income_cents) === updates.monthly_income_cents
        && Number(current.monthly_budget_cents) === updates.monthly_budget_cents;
      if (unchanged) {
        savedUser = current;
        DB.exec('COMMIT');
      } else {
        DB.prepare('UPDATE users SET monthly_income_cents = ?, monthly_budget_cents = ?, updated_at = ? WHERE id = ?')
          .run(updates.monthly_income_cents, updates.monthly_budget_cents, nowISO(), session.user.id);
        DB.exec('COMMIT');
        savedUser = DB.prepare('SELECT * FROM users WHERE id = ?').get(session.user.id);
      }
    } catch (error) {
      try { DB.exec('ROLLBACK'); } catch { /* transação já finalizada */ }
      throw error;
    }
    const publicUser = safePublicUser(savedUser);
    sendJson(res, 200, {
      ...publicUser,
      unchanged,
      message: unchanged ? 'Esses valores já estão salvos.' : 'Preferências financeiras atualizadas com sucesso.'
    });
    return;
  }
  if (pathname.startsWith('/api/account/notifications/') && pathname.endsWith('/read') && method === 'POST') {
    const session = requireSession(req, res); if (!session) return;
    const id = decodeURIComponent(pathname.slice('/api/account/notifications/'.length, -'/read'.length));
    if (!/^[0-9a-f-]{36}$/i.test(id)) { sendError(res, 404, 'Notificação não encontrada.'); return; }
    DB.prepare('UPDATE account_notifications SET read_at=? WHERE id=? AND user_id=? AND read_at IS NULL').run(nowISO(), id, session.user.id);
    sendJson(res, 200, { ok: true }); return;
  }
  if (pathname === '/api/banks' && method === 'POST') {
    const session = requireSession(req, res); if (!session) return;
    const body = await readJson(req); const error = validBankPayload(body);
    if (error) { sendError(res, 400, error); return; }
    const id = crypto.randomUUID(), stamp = nowISO();
    try {
      DB.prepare('INSERT INTO bank_accounts(id,user_id,institution,account_label,created_at,updated_at) VALUES(?,?,?,?,?,?)')
        .run(id, session.user.id, body.institution.trim(), body.accountLabel.trim(), stamp, stamp);
    } catch (e) { if (String(e.message).includes('UNIQUE')) { sendError(res, 409, 'Já existe uma conta com essa instituição e identificação.'); return; } throw e; }
    sendJson(res, 201, { bank: bankAccountRow(DB.prepare('SELECT * FROM bank_accounts WHERE id=? AND user_id=?').get(id, session.user.id)) }); return;
  }
  if (pathname.startsWith('/api/banks/')) {
    const session = requireSession(req, res); if (!session) return;
    const id = decodeURIComponent(pathname.slice('/api/banks/'.length));
    if (!/^[0-9a-f-]{36}$/i.test(id)) { sendError(res, 404, 'Conta bancária não encontrada.'); return; }
    const current = DB.prepare('SELECT * FROM bank_accounts WHERE id=? AND user_id=?').get(id, session.user.id);
    if (!current) { sendError(res, 404, 'Conta bancária não encontrada.'); return; }
    if (method === 'PATCH') {
      const body = await readJson(req); const error = validBankPayload(body, true);
      if (error) { sendError(res, 400, error); return; }
      const merged = { institution: body.institution?.trim() ?? current.institution, accountLabel: body.accountLabel?.trim() ?? current.account_label };
      try { DB.prepare('UPDATE bank_accounts SET institution=?,account_label=?,updated_at=? WHERE id=? AND user_id=?').run(merged.institution, merged.accountLabel, nowISO(), id, session.user.id); }
      catch (e) { if (String(e.message).includes('UNIQUE')) { sendError(res, 409, 'Já existe uma conta com essa instituição e identificação.'); return; } throw e; }
      sendJson(res, 200, { bank: bankAccountRow(DB.prepare('SELECT * FROM bank_accounts WHERE id=? AND user_id=?').get(id, session.user.id)) }); return;
    }
    if (method === 'DELETE') {
      const count = Number(DB.prepare('SELECT COUNT(*) AS n FROM income_records WHERE bank_account_id=? AND user_id=?').get(id, session.user.id).n);
      if (count) { sendError(res, 409, `Esta conta possui ${count} recebimento(s) associado(s). Edite os registros para outra conta antes de excluí-la.`); return; }
      DB.prepare('DELETE FROM bank_accounts WHERE id=? AND user_id=?').run(id, session.user.id);
      sendJson(res, 200, { ok: true }); return;
    }
    res.setHeader('Allow', 'PATCH, DELETE'); sendError(res, 405, 'Método não permitido.'); return;
  }
  if (pathname === '/api/received' && method === 'POST') {
    const session = requireSession(req, res); if (!session) return;
    const body = await readJson(req); const error = validateIncomePayload(body);
    if (error) { sendError(res, 400, error); return; }
    const bank = DB.prepare('SELECT id FROM bank_accounts WHERE id=? AND user_id=?').get(body.bankAccountId, session.user.id);
    if (!bank) { sendError(res, 404, 'A conta bancária selecionada não pertence a esta conta de usuário.'); return; }
    const id = crypto.randomUUID(), stamp = nowISO();
    DB.exec('BEGIN IMMEDIATE');
    try {
      DB.prepare(`INSERT INTO income_records(id,user_id,bank_account_id,amount_cents,received_date,source,payer_name,description,created_at,updated_at)
        VALUES(?,?,?,?,?,?,?,?,?,?)`).run(id, session.user.id, body.bankAccountId, Finance.parseMoneyCents(body.amount), body.receivedDate, body.source.trim(), body.payerName.trim(), (body.description || '').trim(), stamp, stamp);
      DB.exec('COMMIT');
    } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
    const saved = DB.prepare(`SELECT i.*,b.institution AS bank_institution,b.account_label FROM income_records i JOIN bank_accounts b ON b.id=i.bank_account_id AND b.user_id=i.user_id WHERE i.id=? AND i.user_id=?`).get(id, session.user.id);
    sendJson(res, 201, { income: incomeRecordRow(saved) }); return;
  }
  if (pathname.startsWith('/api/received/')) {
    const session = requireSession(req, res); if (!session) return;
    const id = decodeURIComponent(pathname.slice('/api/received/'.length));
    if (!/^[0-9a-f-]{36}$/i.test(id)) { sendError(res, 404, 'Recebimento não encontrado.'); return; }
    const current = DB.prepare('SELECT * FROM income_records WHERE id=? AND user_id=?').get(id, session.user.id);
    if (!current) { sendError(res, 404, 'Recebimento não encontrado.'); return; }
    if (method === 'PATCH') {
      const body = await readJson(req); const error = validateIncomePayload(body, true);
      if (error) { sendError(res, 400, error); return; }
      const merged = {
        amountCents: body.amount === undefined ? current.amount_cents : Finance.parseMoneyCents(body.amount),
        receivedDate: body.receivedDate ?? current.received_date,
        bankAccountId: body.bankAccountId ?? current.bank_account_id,
        source: body.source?.trim() ?? current.source,
        payerName: body.payerName?.trim() ?? current.payer_name,
        description: body.description === undefined ? current.description : body.description.trim()
      };
      const bank = DB.prepare('SELECT id FROM bank_accounts WHERE id=? AND user_id=?').get(merged.bankAccountId, session.user.id);
      if (!bank) { sendError(res, 404, 'A conta bancária selecionada não pertence a esta conta de usuário.'); return; }
      DB.prepare(`UPDATE income_records SET amount_cents=?,received_date=?,bank_account_id=?,source=?,payer_name=?,description=?,updated_at=? WHERE id=? AND user_id=?`)
        .run(merged.amountCents, merged.receivedDate, merged.bankAccountId, merged.source, merged.payerName, merged.description, nowISO(), id, session.user.id);
      const saved = DB.prepare(`SELECT i.*,b.institution AS bank_institution,b.account_label FROM income_records i JOIN bank_accounts b ON b.id=i.bank_account_id AND b.user_id=i.user_id WHERE i.id=? AND i.user_id=?`).get(id, session.user.id);
      sendJson(res, 200, { income: incomeRecordRow(saved) }); return;
    }
    if (method === 'DELETE') {
      DB.prepare('DELETE FROM income_records WHERE id=? AND user_id=?').run(id, session.user.id);
      sendJson(res, 200, { ok: true }); return;
    }
    res.setHeader('Allow', 'PATCH, DELETE'); sendError(res, 405, 'Método não permitido.'); return;
  }

  if (pathname === '/api/expenses' && method === 'POST') {
    const body = await readJson(req);
    const error = validateExpense(body);
    if (error) { sendError(res, 400, error); return; }
    if (body.dueDate && body.dueDate < body.expenseDate) { sendError(res, 400, 'O vencimento não pode ser anterior à data da despesa.'); return; }
    const amountCents = Finance.parseMoneyCents(body.amount);
    const id = crypto.randomUUID(); const stamp = nowISO();
    let recurrenceRuleId = null;
    DB.exec('BEGIN IMMEDIATE');
    try {
      if (body.recurrence !== 'none') {
        recurrenceRuleId = crypto.randomUUID();
        DB.prepare(`INSERT INTO recurrence_rules(id, user_id, description, amount_cents, category, frequency, payment_method, notes, next_date, active, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`)
          .run(recurrenceRuleId, session.user.id, body.description.trim(), amountCents, body.category, body.recurrence, body.paymentMethod, body.notes || '', nextDate(body.expenseDate, body.recurrence), stamp, stamp);
      }
      DB.prepare(`INSERT INTO expenses(id, user_id, recurrence_rule_id, occurrence_date, description, amount_cents, category, expense_date, due_date, status, payment_method, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(id, session.user.id, recurrenceRuleId, recurrenceRuleId ? body.expenseDate : null, body.description.trim(), amountCents, body.category, body.expenseDate, body.dueDate || null, body.status, body.paymentMethod, body.notes || '', stamp, stamp);
      DB.exec('COMMIT');
    } catch (error) { DB.exec('ROLLBACK'); throw error; }
    sendJson(res, 201, { expense: expenseRow(DB.prepare('SELECT * FROM expenses WHERE id = ? AND user_id = ?').get(id, session.user.id)), recurrenceRuleId }); return;
  }
  if (pathname.startsWith('/api/expenses/')) {
    const id = decodeURIComponent(pathname.slice('/api/expenses/'.length));
    if (!/^[0-9a-f-]{36}$/i.test(id)) { sendError(res, 404, 'Despesa não encontrada.'); return; }
    const current = DB.prepare('SELECT * FROM expenses WHERE id = ? AND user_id = ?').get(id, session.user.id);
    if (!current) { sendError(res, 404, 'Despesa não encontrada.'); return; }
    if (method === 'PATCH') {
      const body = await readJson(req);
      const error = validateExpense(body, true);
      if (error) { sendError(res, 400, error); return; }
      const merged = {
        description: body.description === undefined ? current.description : body.description.trim(),
        amountCents: body.amount === undefined ? current.amount_cents : Finance.parseMoneyCents(body.amount),
        category: body.category === undefined ? current.category : body.category,
        expenseDate: body.expenseDate === undefined ? current.expense_date : body.expenseDate,
        dueDate: body.dueDate === undefined ? current.due_date : (body.dueDate || null),
        status: body.status === undefined ? current.status : body.status,
        paymentMethod: body.paymentMethod === undefined ? current.payment_method : body.paymentMethod,
        notes: body.notes === undefined ? current.notes : body.notes
      };
      if (!isAllowedExpenseDate(merged.expenseDate) || !isAllowedExpenseDate(merged.dueDate, true)) { sendError(res, 400, 'A data não pode ser anterior a 1950.'); return; }
      if (merged.dueDate && merged.dueDate < merged.expenseDate) { sendError(res, 400, 'O vencimento não pode ser anterior à data da despesa.'); return; }
      const stamp = nowISO();
      DB.prepare(`UPDATE expenses SET description=?, amount_cents=?, category=?, expense_date=?, due_date=?, status=?, completed_at=?, payment_method=?, notes=?, updated_at=? WHERE id=? AND user_id=?`)
        .run(merged.description, merged.amountCents, merged.category, merged.expenseDate, merged.dueDate, merged.status, merged.status === 'paid' ? (current.status === 'paid' ? current.completed_at || stamp : stamp) : null, merged.paymentMethod, merged.notes, stamp, id, session.user.id);
      sendJson(res, 200, { expense: expenseRow(DB.prepare('SELECT * FROM expenses WHERE id = ? AND user_id = ?').get(id, session.user.id)) }); return;
    }
    if (method === 'DELETE') {
      DB.prepare('DELETE FROM expenses WHERE id = ? AND user_id = ?').run(id, session.user.id);
      sendJson(res, 200, { ok: true, recurringSeriesContinues: Boolean(current.recurrence_rule_id) }); return;
    }
    res.setHeader('Allow', 'PATCH, DELETE'); sendError(res, 405, 'Método não permitido.'); return;
  }
  if (pathname.startsWith('/api/recurrences/')) {
    const id = decodeURIComponent(pathname.slice('/api/recurrences/'.length));
    if (!/^[0-9a-f-]{36}$/i.test(id)) { sendError(res, 404, 'Recorrência não encontrada.'); return; }
    if (method !== 'PATCH') { res.setHeader('Allow', 'PATCH'); sendError(res, 405, 'Método não permitido.'); return; }
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['active']) || typeof body.active !== 'boolean') { sendError(res, 400, 'Informe se a recorrência ficará ativa.'); return; }
    const result = DB.prepare('UPDATE recurrence_rules SET active = ?, updated_at = ? WHERE id = ? AND user_id = ?').run(body.active ? 1 : 0, nowISO(), id, session.user.id);
    if (!result.changes) { sendError(res, 404, 'Recorrência não encontrada.'); return; }
    sendJson(res, 200, { ok: true }); return;
  }
  if (pathname === '/api/calculations' && method === 'POST') {
    const body = await readJson(req);
    const allowed = ['description', 'price', 'downPayment', 'fees', 'count', 'monthlyInterestPercent', 'monthlyBudget'];
    if (!isPlainObject(body) || !hasOnlyKeys(body, allowed)) { sendError(res, 400, 'A simulação contém campos inválidos.'); return; }
    if (body.description !== undefined && !validateText(body.description, 120)) { sendError(res, 400, 'A descrição deve ter até 120 caracteres.'); return; }
    const amounts = {};
    for (const [field, value] of [['price', body.price], ['downPayment', body.downPayment ?? '0'], ['fees', body.fees ?? '0'], ['monthlyBudget', body.monthlyBudget ?? '0']]) {
      amounts[field] = Finance.parseMoneyCents(value);
      if (!Number.isSafeInteger(amounts[field]) || amounts[field] < 0 || amounts[field] > 9_000_000_000_000) { sendError(res, 400, `Informe um valor válido para ${field === 'price' ? 'o preço' : field === 'downPayment' ? 'a entrada' : field === 'fees' ? 'os encargos' : 'o orçamento mensal'}.`); return; }
    }
    const count = Number(body.count);
    const rate = Number(body.monthlyInterestPercent ?? 0);
    if (!Number.isInteger(count) || count < 1 || count > 120) { sendError(res, 400, 'O número de parcelas deve ficar entre 1 e 120.'); return; }
    if (!Number.isFinite(rate) || rate < 0 || rate > 50) { sendError(res, 400, 'A taxa mensal deve ficar entre 0% e 50%.'); return; }
    try {
      const result = Finance.calculateInstallment({ priceCents: amounts.price, downPaymentCents: amounts.downPayment, feeCents: amounts.fees, count, monthlyInterestBps: Math.round(rate * 100), monthlyBudgetCents: amounts.monthlyBudget });
      const id = crypto.randomUUID(); const stamp = nowISO();
      DB.exec('BEGIN IMMEDIATE');
      try {
        const plan = Plans.planFor(session.user.plan);
        const countSaved = Number(DB.prepare('SELECT COUNT(*) AS total FROM installment_calculations WHERE user_id = ?').get(session.user.id).total);
        if (plan === 'base' && countSaved >= Plans.BASE_CALCULATION_LIMIT) {
          DB.exec('ROLLBACK');
          sendError(res, 403, 'Você atingiu o limite de 5 planos salvos do Base. O Premium permite salvar quantos planos precisar.', { code: 'CALCULATION_LIMIT_REACHED', upgrade: true, limit: Plans.BASE_CALCULATION_LIMIT, used: countSaved });
          return;
        }
        DB.prepare(`INSERT INTO installment_calculations(id, user_id, item_description, price_cents, down_payment_cents, fee_cents, installment_count, monthly_interest_bps, financed_cents, installment_cents, installments_total_cents, total_paid_cents, interest_and_fees_cents, monthly_budget_cents, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
          .run(id, session.user.id, (body.description || '').trim(), result.priceCents, result.downPaymentCents, result.feeCents, result.count, result.monthlyInterestBps, result.financedCents, result.installmentCents, result.installmentsTotalCents, result.totalPaidCents, result.interestAndFeesCents, result.monthlyBudgetCents, stamp);
        DB.exec('COMMIT');
      } catch (error) {
        try { DB.exec('ROLLBACK'); } catch { /* transação já finalizada */ }
        throw error;
      }
      sendJson(res, 201, { calculation: { ...result, id, description: (body.description || '').trim(), createdAt: stamp } });
    } catch (error) {
      if (error instanceof RangeError || error instanceof TypeError) { sendError(res, 400, error.message); return; }
      throw error;
    }
    return;
  }
  if (pathname.startsWith('/api/calculations/')) {
    const id = decodeURIComponent(pathname.slice('/api/calculations/'.length));
    if (!/^[0-9a-f-]{36}$/i.test(id)) { sendError(res, 404, 'Simulação não encontrada.'); return; }
    if (method !== 'DELETE') { res.setHeader('Allow', 'DELETE'); sendError(res, 405, 'Método não permitido.'); return; }
    const result = DB.prepare('DELETE FROM installment_calculations WHERE id = ? AND user_id = ?').run(id, session.user.id);
    if (!result.changes) { sendError(res, 404, 'Simulação não encontrada.'); return; }
    sendJson(res, 200, { ok: true }); return;
  }
  if (pathname === '/api/account' && method === 'DELETE') {
    const body = await readJson(req);
    if (!isPlainObject(body) || !hasOnlyKeys(body, ['password']) || !validateText(body.password, 128, true)) {
      sendError(res, 400, 'Confirme sua senha atual para excluir a conta.'); return;
    }
    const user = DB.prepare("SELECT * FROM users WHERE id=? AND account_status='active'").get(session.user.id);
    if (!user) { sendError(res, 404, 'Conta não encontrada.'); return; }
    const windowStart = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    const failures = Number(DB.prepare(`SELECT COUNT(*) AS n FROM user_security_events
      WHERE user_id=? AND event_type='self_account_delete_failed' AND created_at>=?`).get(session.user.id, windowStart).n || 0);
    if (failures >= 5) { sendError(res, 429, 'Muitas tentativas de confirmação. Aguarde 15 minutos antes de tentar novamente.', { code: 'ACCOUNT_DELETE_RATE_LIMITED', retryAfterSeconds: 900 }); return; }
    const ipHash = registrationIpHashFromAddress(requestIp(req));
    if (!(await verifyPassword(body.password, user.password_salt, user.password_hash))) {
      DB.prepare(`INSERT INTO user_security_events(id,user_id,event_type,source_ip_hash,details_json,created_at)
        VALUES(?,?,'self_account_delete_failed',?,?,?)`)
        .run(crypto.randomUUID(), session.user.id, ipHash, JSON.stringify({ windowMinutes: 15 }), nowISO());
      sendError(res, 403, 'Senha incorreta. Não foi possível confirmar sua identidade.'); return;
    }
    if (DB.prepare('SELECT id FROM payment_records WHERE user_id=? LIMIT 1').get(session.user.id)) {
      DB.prepare(`INSERT INTO user_security_events(id,user_id,event_type,source_ip_hash,details_json,created_at)
        VALUES(?,?,'self_account_delete_assistance_required',?,?,?)`)
        .run(crypto.randomUUID(), session.user.id, ipHash, JSON.stringify({ reason: 'payment_records_retention' }), nowISO());
      sendError(res, 409, 'Sua conta possui histórico de cobranças que precisa ser preservado. Entre em contato com o suporte para solicitar a exclusão assistida.'); return;
    }
    const openSubscription = DB.prepare("SELECT id,provider_subscription_id FROM payment_subscriptions WHERE user_id=? AND status IN ('creating','pending','authorized','trialing','active','past_due') ORDER BY created_at DESC LIMIT 1").get(session.user.id);
    if (openSubscription?.provider_subscription_id) {
      try {
        const canceled = await MercadoPago.cancelSubscription(openSubscription.provider_subscription_id);
        if (canceled?.status && !['canceled','cancelled'].includes(String(canceled.status))) throw new Error('Não confirmado');
      } catch {
        sendError(res, 502, 'Não foi possível confirmar o cancelamento da assinatura no provedor. A conta foi mantida.'); return;
      }
    }
    DB.exec('BEGIN IMMEDIATE');
    try {
      const stamp = nowISO();
      if (openSubscription) DB.prepare("UPDATE payment_subscriptions SET status='canceled',provider_status='canceled',canceled_at=COALESCE(canceled_at,?),updated_at=? WHERE id=?").run(stamp, stamp, openSubscription.id);
      // Grava apenas o evento mínimo e pseudonimizado. O FK SET NULL desvincula
      // o evento da conta removida sem reter nome, e-mail, senha ou dados financeiros.
      DB.prepare(`INSERT INTO user_security_events(id,user_id,event_type,source_ip_hash,details_json,created_at)
        VALUES(?,?,'self_account_deleted',?,?,?)`)
        .run(crypto.randomUUID(), session.user.id, ipHash, JSON.stringify({ method: 'self_service', linkedAccountsDetached: true }), stamp);
      // Grupos pertencentes à conta são encerrados e apenas os vínculos dos demais
      // usuários são removidos; seus registros e contas permanecem intactos.
      detachAccountGroupsForDeactivation(session.user.id);
      DB.prepare('DELETE FROM users WHERE id=?').run(session.user.id);
      DB.exec('COMMIT');
    } catch (error) { try { DB.exec('ROLLBACK'); } catch {} throw error; }
    sendJson(res, 200, { ok: true, message: 'Sua conta foi excluída conforme sua solicitação. O acesso foi encerrado e os dados associados foram removidos.' }, { 'Set-Cookie': clearCookie() }); return;
  }

  if (pathname.startsWith('/api/')) { sendError(res, 404, 'Endpoint da API não encontrado.'); return; }
  res.setHeader('Allow', 'GET, HEAD'); sendError(res, 405, 'Método não permitido.');
}

const server = http.createServer({ maxHeaderSize: 16 * 1024 }, (req, res) => {
  handleRequest(req, res).catch((error) => {
    if (error && error.code && ['SQLITE_CONSTRAINT_UNIQUE', 'SQLITE_CONSTRAINT_CHECK', 'SQLITE_CONSTRAINT_FOREIGNKEY'].includes(error.code)) {
      if (!res.headersSent) sendError(res, 400, 'Os dados não passaram pelas validações exigidas.'); else res.destroy();
      return;
    }
    if (error && [400, 408, 413, 415].includes(error.statusCode)) {
      if (!res.headersSent) sendError(res, error.statusCode, error.message); else res.destroy();
      return;
    }
    process.stderr.write(`[OVBECK] Erro interno (${error && error.code ? error.code : 'sem código'}).\n`);
    if (!res.headersSent) sendError(res, 500, 'Ocorreu um erro interno. Tente novamente.'); else res.destroy();
  });
});
server.headersTimeout = 10_000;
server.requestTimeout = 15_000;
server.keepAliveTimeout = 5_000;
server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') process.stderr.write(`A porta ${PORT} já está em uso. Feche outra instância ou altere PORT.\n`);
  else if (error.code === 'ENOTFOUND' || error.code === 'EADDRNOTAVAIL') process.stderr.write(`Endereço local inválido: ${JSON.stringify(HOST)}.\n`);
  else process.stderr.write(`Falha ao iniciar o servidor (${error.code || 'erro'}).\n`);
  process.exitCode = 1;
});
server.on('close', () => { try { DB.close(); } catch { /* já fechado */ } });

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    const address = server.address();
    process.stdout.write(`\nOVBECK disponível em http://${HOST}:${address.port}\n`);
    process.stdout.write(`Banco SQLite local: ${path.relative(ROOT, process.env.DATABASE_PATH || path.join(DATA_DIR, 'finance.sqlite'))}\n`);
    process.stdout.write('Cadastre sua conta para começar. Dados de cada conta são isolados no backend. Use Ctrl+C para encerrar.\n\n');
  });
  const shutdown = () => server.close(() => process.exit(0));
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

module.exports = { server, DB, handleRequest, hashPassword, verifyPassword, validateExpense, validateNewUser, isValidFullName, isValidEmailAddress, isValidNewPassword, normalizeFullName, dashboard, minimumExpenseDate, isAllowedExpenseDate };
