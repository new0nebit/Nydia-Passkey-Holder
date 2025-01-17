import { getSettings, saveStoredCredential } from './store';
import { RenterdSettings, StoredCredential } from './types';
import { logInfo, logError } from './logger';

// Create Basic Auth headers for renterd API.
function createRenterdHeaders(settings: RenterdSettings, contentType?: string): HeadersInit {
  const headers: HeadersInit = {
    'Authorization': 'Basic ' + btoa(`root:${settings.password}`),
  };
  if (contentType) {
    headers['Content-Type'] = contentType;
  }
  return headers;
}

// Build a URL to list objects in the renterd bucket.
function buildRenterdObjectListURL(settings: RenterdSettings, prefix = ''): string {
  return `http://${settings.serverAddress}:${settings.serverPort}/api/bus/objects/${encodeURIComponent(prefix)}?bucket=${settings.bucketName}`;
}

// Build a URL for uploading/downloading a passkey.
function buildRenterdObjectURL(settings: RenterdSettings, fileName?: string): string {
  const baseUrl = `http://${settings.serverAddress}:${settings.serverPort}/api/worker/object`;
  const bucketParam = `?bucket=${settings.bucketName}`;
  return fileName
    ? `${baseUrl}/${encodeURIComponent(fileName)}${bucketParam}`
    : `${baseUrl}/${bucketParam}`;
}

// Send the request, check for errors, log the result.
async function makeRequest(url: string, options: RequestInit): Promise<Response> {
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
export async function getPasskeysFromRenterd(settings: RenterdSettings): Promise<string[]> {
  logInfo('Starting getPasskeysFromRenterd', { settings });

  const url = buildRenterdObjectListURL(settings);
  const headers = createRenterdHeaders(settings);

  try {
    const response = await makeRequest(url, { method: 'GET', headers });
    const json = await response.json();
    logInfo('Parsed objects list', json);

    const objects = json.objects || [];
    const jsonFiles = objects
      .map((obj: any) => obj.key)
      .filter((key: string) => key.endsWith('.json'))
      .map((key: string) => key.replace(/^\//, ''));

    return jsonFiles;
  } catch (error) {
    logError('Error getting passkeys from renterd', error);
    throw error;
  }
}

// Upload a passkey to renterd under the uniqueId name.
async function uploadPasskeyToRenterd(
  fileContent: Blob | null,
  fileName: string,
  settings: RenterdSettings,
  testConnection = false
): Promise<void> {
  logInfo('Starting uploadPasskeyToRenterd', { fileName, settings });

  const url = buildRenterdObjectURL(settings, fileName);
  const headers = createRenterdHeaders(settings, 'application/octet-stream');

  try {
    await makeRequest(url, {
      method: 'PUT',
      headers,
      body: testConnection ? undefined : fileContent,
    });
    logInfo('File successfully uploaded to renterd', { fileName });
  } catch (error) {
    logError('Error uploading passkey to renterd', error);
    throw error;
  }
}

// Download a passkey from renterd and return it as StoredCredential.
export async function downloadPasskeyFromRenterd(
  fileName: string,
  settings: RenterdSettings
): Promise<StoredCredential> {
  logInfo('Starting downloadPasskeyFromRenterd', { fileName, settings });

  const url = buildRenterdObjectURL(settings, fileName);
  const headers = createRenterdHeaders(settings);

  try {
    const response = await makeRequest(url, { method: 'GET', headers });
    const data = await response.json();
    logInfo('Downloaded passkey data', Object.keys(data));
    return data as StoredCredential;
  } catch (error) {
    logError(`Error downloading passkey ${fileName} from renterd`, error);
    throw error;
  }
}

// Upload a passkey and mark it as synced in IndexedDB.
export async function uploadPasskeyDirect(
  passkey: StoredCredential
): Promise<{ success: boolean; message?: string; error?: string }> {
  const settings = await getSettings();
  if (!settings) {
    return {
      success: false,
      error: 'Please configure renterd settings first.',
    };
  }

  const passkeyDataJson = JSON.stringify(passkey, null, 2);
  const blob = new Blob([passkeyDataJson], { type: 'application/json' });

  try {
    await uploadPasskeyToRenterd(blob, `${passkey.uniqueId}.json`, settings);
    passkey.isSynced = true;
    await saveStoredCredential(passkey);

    logInfo('Passkey uploaded successfully', { uniqueId: passkey.uniqueId });
    return {
      success: true,
      message: 'Passkey successfully backed up to Sia.',
    };
  } catch (error: any) {
    logError('Error uploading passkey to renterd', error);
    return {
      success: false,
      error: `Failed to backup passkey: ${error.message}`,
    };
  }
}
