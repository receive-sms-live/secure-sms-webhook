/// <reference types="node" />

export type Provider = 'twilio' | 'telnyx' | 'vonage' | 'plivo' | 'generic-hmac';
export type SignatureEncoding = 'hex' | 'base64' | 'base64url';
export interface VerificationResult {
  valid: boolean;
  provider: string;
  code: string;
  message: string;
  [key: string]: unknown;
}
export interface ReplayStore {
  claim(key: string, ttlMs: number, now?: number): Promise<boolean> | boolean;
  delete?(key: string): Promise<boolean> | boolean;
}
export interface HmacOptions {
  rawBody: string | Buffer;
  signature?: string;
  secret: string;
  algorithm?: 'sha1' | 'sha224' | 'sha256' | 'sha384' | 'sha512';
  encoding?: SignatureEncoding;
  prefix?: string;
  timestamp?: string | number;
  timestampSeparator?: string;
  requireTimestamp?: boolean;
  maxAgeSeconds?: number | false;
  maxFutureSkewSeconds?: number;
  now?: number;
}
export function createHmacSignature(options: HmacOptions): string;
export function verifyHmacWebhook(options: HmacOptions): VerificationResult;

export interface TwilioOptions {
  url: string;
  params?: Record<string, string | string[]>;
  rawBody?: string | Buffer;
  signature?: string;
  authToken: string;
  contentType?: string;
}
export function createTwilioSignature(options: Pick<TwilioOptions, 'url' | 'params' | 'authToken'>): string;
export function verifyTwilioWebhook(options: TwilioOptions): VerificationResult;

export interface TelnyxOptions {
  rawBody: string | Buffer;
  signature?: string;
  timestamp: string | number;
  publicKey: string | Buffer;
  maxAgeSeconds?: number | false;
  maxFutureSkewSeconds?: number;
  now?: number;
}
export function createTelnyxTestSignature(options: {
  rawBody: string | Buffer;
  timestamp: string | number;
  privateKey: string | Buffer | object;
}): string;
export function verifyTelnyxWebhook(options: TelnyxOptions): VerificationResult;

export interface VonageOptions {
  params: Record<string, unknown>;
  signature?: string;
  secret: string;
  algorithm?: 'sha1' | 'sha256' | 'sha512';
  maxAgeSeconds?: number | false;
  maxFutureSkewSeconds?: number;
  now?: number;
}
export function createVonageSignature(options: Pick<VonageOptions, 'params' | 'secret' | 'algorithm'>): string;
export function verifyVonageWebhook(options: VonageOptions): VerificationResult;

export interface PlivoOptions {
  url: string;
  params?: Record<string, unknown>;
  signature?: string;
  nonce: string;
  authToken: string;
  method?: 'GET' | 'POST';
}
export function createPlivoSignature(options: Omit<PlivoOptions, 'signature'>): string;
export function verifyPlivoWebhook(options: PlivoOptions): VerificationResult;

export function validateTimestamp(options: {
  timestamp: string | number;
  maxAgeSeconds?: number;
  maxFutureSkewSeconds?: number;
  now?: number;
}): VerificationResult;
export interface NormalizedSmsPayload {
  from?: unknown;
  to?: unknown;
  body?: unknown;
  eventId?: unknown;
  original?: unknown;
}
export function normalizeSmsPayload(
  provider: Provider,
  payload: Record<string, unknown>,
  customFields?: Record<string, string>,
): NormalizedSmsPayload | null;
export function validateSmsPayload(
  payload: NormalizedSmsPayload,
  options?: Record<string, unknown>,
): { valid: boolean; errors: object[]; warnings: object[] };
export const E164_PATTERN: RegExp;

export class MemoryReplayStore implements ReplayStore {
  constructor(options?: { maxEntries?: number });
  readonly maxEntries: number;
  readonly size: number;
  claim(key: string, ttlMs: number, now?: number): Promise<boolean>;
  delete(key: string): Promise<boolean>;
}
export function createReplayKey(options?: Record<string, unknown>): string;
export function protectAgainstReplay(options: {
  store: ReplayStore;
  provider?: string;
  eventId?: string;
  rawBody?: string | Buffer;
  signature?: string;
  ttlMs?: number;
  now?: number;
}): Promise<VerificationResult>;
export function redactWebhook<T>(value: T, options?: {
  phoneNumbers?: boolean;
  otp?: boolean;
  email?: boolean;
}): T;

export const PROVIDERS: readonly Provider[];
export function verifyProviderWebhook(options: Record<string, unknown> & { provider: Provider }): VerificationResult;
export function secureWebhook(options: Record<string, unknown> & {
  provider: Provider;
  replayStore?: ReplayStore;
  replayTtlMs?: number;
  payloadValidation?: boolean;
}): Promise<VerificationResult>;
export function captureRawBody(req: object, res: object, buffer: Buffer): void;
export function createExpressMiddleware(config: Record<string, unknown> & { provider: Provider }): Function;
