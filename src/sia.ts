import { logDebug, logError } from './logger';
import { getSettings } from './store';
import { EncryptedRecord, RenterdSettings } from './types';

const PASSKEY_EXTENSION = '.passkey';
const MIME_OCTET_STREAM = 'application/octet-stream';
const QUERY_BUCKET = 'bucket';
const QUERY_MIMETYPE = 'mimetype';

// Build base URL using saved protocol (detected during settings save).
function buildBaseURL(settings: RenterdSettings): string {
  const protocol = settings.serverProtocol ?? 'http';
  return `${protocol}://${settings.serverAddress}:${settings.serverPort}`;
}

// Base URL builders.
function buildWorkerBaseURL(settings: RenterdSettings): string {
  return `${buildBaseURL(settings)}/api/worker/object`;
}

function buildBusBaseURL(settings: RenterdSettings): string {
  return `${buildBaseURL(settings)}/api/bus`;
}

// Build a URL to list objects in the renterd bucket.
function buildListURL(settings: RenterdSettings, prefix = ''): string {
  return (
    `${buildBusBaseURL(settings)}/objects/${encodeURIComponent(prefix)}` +
    `?${QUERY_BUCKET}=${settings.bucketName}`
  );
}

// Build a URL for uploading/downloading a passkey.
function buildObjectURL(settings: RenterdSettings, fileName: string): string {
  return (
    `${buildWorkerBaseURL(settings)}/${encodeURIComponent(fileName)}` +
    `?${QUERY_BUCKET}=${settings.bucketName}`
  );
}

// URL for PUT uploads.
function buildUploadURL(settings: RenterdSettings, fileName: string): string {
  return (
    `${buildWorkerBaseURL(settings)}/${encodeURIComponent(fileName)}` +
    `?${QUERY_BUCKET}=${settings.bucketName}` +
    `&${QUERY_MIMETYPE}=${encodeURIComponent(MIME_OCTET_STREAM)}`
  );
}

// Create Basic Auth headers for renterd API.
function buildHeaders(
  settings: RenterdSettings,
  contentType?: string,
): HeadersInit {
  const headerMap: HeadersInit = {
    Authorization: 'Basic ' + btoa(`username:${settings.password}`),
  };
  if (contentType) headerMap['Content-Type'] = contentType;
  return headerMap;
}

// Send the request, check for errors, log the result.
async function httpRequest(
  url: string,
  options: RequestInit,
): Promise<Response> {
  logDebug('[Sia] Sending request', { url, options });
  const response = await fetch(url, options);
  logDebug('[Sia] Response status', { status: response.status });

  if (!response.ok) {
    const errorText = `HTTP error! Status: ${response.status} ${response.statusText}`;
    logError('[Sia] Non-successful server response', errorText);
    throw new Error(errorText);
  }
  return response;
}

// Get a list of passkeys from the bucket.
export async function getPasskeysFromRenterd(
  settings: RenterdSettings,
): Promise<string[]> {
  logDebug('[Sia] Starting getPasskeysFromRenterd', { settings });

  const response = await httpRequest(buildListURL(settings), {
    method: 'GET',
    headers: buildHeaders(settings),
  });
  const jsonData = (await response.json()) as { objects?: Array<{ key: string }> };
  logDebug('[Sia] Parsed objects list', jsonData);

  const objects = jsonData.objects ?? [];
  const passkeyFiles = objects
    .map((object) => object.key.replace(/^\//, ''))
    .filter((key) => key.endsWith(PASSKEY_EXTENSION));

  logDebug('[Sia] Found passkey files', { count: passkeyFiles.length, files: passkeyFiles });
  return passkeyFiles;
}

// Upload a passkey to renterd under the uniqueId name.
async function uploadPasskeyToRenterd(
  passkeyData: Blob,
  uniqueId: string,
  settings: RenterdSettings,
): Promise<void> {
  const fileName = `${uniqueId}${PASSKEY_EXTENSION}`;
  logDebug('[Sia] Starting uploadPasskeyToRenterd', { fileName, settings });

  await httpRequest(buildUploadURL(settings, fileName), {
    method: 'PUT',
    headers: buildHeaders(settings, MIME_OCTET_STREAM),
    body: passkeyData,
  });
  logDebug('[Sia] Binary passkey blob stored on renterd', { fileName });
}

// Download a passkey from renterd and return it as EncryptedRecord.
export async function downloadPasskeyFromRenterd(
  fileName: string,
  settings: RenterdSettings,
): Promise<EncryptedRecord> {
  logDebug('[Sia] Starting downloadPasskeyFromRenterd', { fileName, settings });

  const response = await httpRequest(buildObjectURL(settings, fileName), {
    method: 'GET',
    headers: buildHeaders(settings),
  });
  const data = await response.json();
  logDebug('[Sia] Downloaded encrypted passkey data', { uniqueId: data.uniqueId });

  // Validate that it's a proper EncryptedRecord.
  if (!data.uniqueId || !data.iv || !data.data) {
    throw new Error('Invalid encrypted record format');
  }

  return data as EncryptedRecord;
}

// Upload an encrypted passkey record to renterd.
export async function uploadPasskeyDirect(
  record: EncryptedRecord,
): Promise<{ success: boolean; message?: string; error?: string }> {
  const settings = await getSettings();
  if (!settings) {
    return {
      success: false,
      error: 'Please configure renterd settings first.',
    };
  }

  // Clone record and mark as synced.
  const recordToUpload = { ...record, isSynced: true };
  const passkeyDataJson = JSON.stringify(recordToUpload, null, 2);
  const passkeyData = new Blob([passkeyDataJson], {
    type: MIME_OCTET_STREAM,
  });

  try {
    await uploadPasskeyToRenterd(passkeyData, record.uniqueId, settings);
    logDebug('[Sia] Encrypted record prepared and uploaded via renterd worker API', {
      uniqueId: record.uniqueId,
    });
    return {
      success: true,
      message: 'Passkey successfully backed up to Sia.',
    };
  } catch (error: unknown) {
    logError('[Sia] Error uploading encrypted passkey to renterd', error);
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      error: `Failed to backup passkey: ${message}`,
    };
  }
}
