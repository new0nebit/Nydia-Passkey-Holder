import { logInfo, logError } from './logger';
import { getSettings } from './store';
import { EncryptedRecord, RenterdSettings } from './types';

const PASSKEY_EXTENSION = '.passkey';
const MIME_OCTET_STREAM = 'application/octet-stream';
const QUERY_BUCKET = 'bucket';
const QUERY_MIMETYPE = 'mimetype';

// Base URL builders.
function buildWorkerBaseURL(settings: RenterdSettings): string {
  return `http://${settings.serverAddress}:${settings.serverPort}/api/worker/object`;
}

function buildBusBaseURL(settings: RenterdSettings): string {
  return `http://${settings.serverAddress}:${settings.serverPort}/api/bus`;
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
  logInfo('Sending request', { url, options });
  const response = await fetch(url, options);
  logInfo('Response status', { status: response.status });

  if (!response.ok) {
    const errorText = `HTTP error! Status: ${response.status} ${response.statusText}`;
    logError('Non-successful server response', errorText);
    throw new Error(errorText);
  }
  return response;
}

// Get a list of passkeys from the bucket.
export async function getPasskeysFromRenterd(
  settings: RenterdSettings,
): Promise<string[]> {
  logInfo('Starting getPasskeysFromRenterd', { settings });

  const response = await httpRequest(buildListURL(settings), {
    method: 'GET',
    headers: buildHeaders(settings),
  });
  const jsonData = await response.json();
  logInfo('Parsed objects list', jsonData);

  const objects = jsonData.objects || [];
  const passkeyFiles = objects
    .map((object: any) => (object.key as string).replace(/^\//, ''))
    .filter((key: string) => key.endsWith(PASSKEY_EXTENSION));

  logInfo('Found passkey files', { count: passkeyFiles.length, files: passkeyFiles });
  return passkeyFiles;
}

// Upload a passkey to renterd under the uniqueId name.
async function uploadPasskeyToRenterd(
  passkeyData: Blob | null,
  uniqueId: string,
  settings: RenterdSettings,
  testConnection = false,
): Promise<void> {
  const fileName = `${uniqueId}${PASSKEY_EXTENSION}`;
  logInfo('Starting uploadPasskeyToRenterd', { fileName, settings, testConnection });

  await httpRequest(buildUploadURL(settings, fileName), {
    method: 'PUT',
    headers: buildHeaders(settings, MIME_OCTET_STREAM),
    body: testConnection ? undefined : passkeyData,
  });
  logInfo('Binary passkey blob stored on renterd', { fileName });
}

// Download a passkey from renterd and return it as EncryptedRecord.
export async function downloadPasskeyFromRenterd(
  fileName: string,
  settings: RenterdSettings,
): Promise<EncryptedRecord> {
  logInfo('Starting downloadPasskeyFromRenterd', { fileName, settings });

  const response = await httpRequest(buildObjectURL(settings, fileName), {
    method: 'GET',
    headers: buildHeaders(settings),
  });
  const data = await response.json();
  logInfo('Downloaded encrypted passkey data', { uniqueId: data.uniqueId });

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

  // Mark record as synced before upload.
  (record as any).isSynced = true;
  const passkeyDataJson = JSON.stringify(record, null, 2);
  const passkeyData = new Blob([passkeyDataJson], {
    type: MIME_OCTET_STREAM,
  });

  try {
    await uploadPasskeyToRenterd(passkeyData, record.uniqueId, settings);
    logInfo('Encrypted record prepared and uploaded via renterd worker API', {
      uniqueId: record.uniqueId,
    });
    return {
      success: true,
      message: 'Passkey successfully backed up to Sia.',
    };
  } catch (error: any) {
    logError('Error uploading encrypted passkey to renterd', error);
    return {
      success: false,
      error: `Failed to backup passkey: ${error.message}`,
    };
  }
}
