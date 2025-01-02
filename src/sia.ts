import { getSettings, saveStoredCredential } from './store';
import { RenterdSettings, StoredCredential } from './types';
import { logInfo, logError } from './logger';

/**
 * Creates authorization headers for the renterd requests. 
 * Content-Type is optional and can be specified if needed.
 * @param settings - RenterdSettings object.
 * @param contentType - Optional content type for the request.
 * @returns HeadersInit with proper authorization and optional content type.
 */
function createRenterdHeaders(settings: RenterdSettings, contentType?: string): HeadersInit {
  const headers: HeadersInit = {
    'Authorization': 'Basic ' + btoa(`root:${settings.password}`),
  };
  if (contentType) {
    headers['Content-Type'] = contentType;
  }
  return headers;
}

/**
 * Builds the full URL for the renterd requests.
 * @param settings - RenterdSettings object containing serverAddress, serverPort, bucketName.
 * @param fileName - Optional fileName to construct a URL pointing to a specific object.
 * @returns A string with the full URL including the bucket parameter.
 */
function buildRenterdURL(settings: RenterdSettings, fileName?: string): string {
  const baseUrl = `http://${settings.serverAddress}:${settings.serverPort}/api/worker/objects`;
  const bucketParam = `?bucket=${settings.bucketName}`;
  return fileName
    ? `${baseUrl}/${encodeURIComponent(fileName)}${bucketParam}`
    : `${baseUrl}/${bucketParam}`;
}

/**
 * Makes a fetch request and handles logging and error checking.
 * @param url - The URL to request.
 * @param options - RequestInit options for fetch.
 * @returns The fetched Response if successful.
 * @throws An Error if the response is not ok.
 */
async function makeRequest(url: string, options: RequestInit): Promise<Response> {
  // Mask the password before logging settings if provided in headers
  // Since in this code we do not directly log settings in makeRequest, 
  // we just proceed with normal logging of request info.
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

/**
 * Uploads a passkey to renterd.
 * @param fileContent - The file content to upload (as Blob).
 * @param fileName - The name of the file to be stored on renterd.
 * @param settings - RenterdSettings for server connection.
 * @param testConnection - If true, the request is made without a body, used for testing connection.
 * @returns A promise that resolves if the upload is successful.
 * @throws An Error if the upload fails.
 */
async function uploadPasskeyToRenterd(
  fileContent: Blob | null,
  fileName: string,
  settings: RenterdSettings,
  testConnection = false
): Promise<void> {
  const url = buildRenterdURL(settings, fileName);
  const headers = createRenterdHeaders(settings, 'application/octet-stream');

  // Mask password in logs
  const maskedSettings = { ...settings, password: '******' };
  logInfo('Starting uploadPasskeyToRenterd', { fileName, settings: maskedSettings });

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

/**
 * Retrieves a list of passkeys from renterd.
 * @param settings - RenterdSettings for server connection.
 * @returns An array of file names (strings) representing passkeys stored in renterd.
 * @throws An Error if retrieving the list fails.
 */
export async function getPasskeysFromRenterd(settings: RenterdSettings): Promise<string[]> {
  // Mask password in logs
  const maskedSettings = { ...settings, password: '******' };
  logInfo('Starting getPasskeysFromRenterd with settings', maskedSettings);

  const url = buildRenterdURL(settings);
  const headers = createRenterdHeaders(settings);

  try {
    const response = await makeRequest(url, {
      method: 'GET',
      headers,
    });

    // Get raw response for logging
    const rawResponse = await response.text();
    logInfo('Raw API response (objects list)', rawResponse);

    // Parse JSON
    const objects = JSON.parse(rawResponse);
    logInfo('Parsed objects list', objects);

    // Filter only .json files and remove leading slash
    const jsonFiles = objects
      .filter((obj: any) => obj.name.endsWith('.json'))
      .map((obj: any) => obj.name.replace(/^\//, ''));

    logInfo('Filtered JSON files', jsonFiles);
    return jsonFiles;

  } catch (error) {
    logError('Error getting passkeys from renterd', error);
    throw error;
  }
}

/**
 * Downloads a single passkey from renterd.
 * @param fileName - The name of the passkey file to download.
 * @param settings - RenterdSettings for server connection.
 * @returns The parsed passkey data as a StoredCredential.
 * @throws An Error if downloading the passkey fails.
 */
export async function downloadPasskeyFromRenterd(
  fileName: string,
  settings: RenterdSettings
): Promise<StoredCredential> {
  // Mask password in logs
  const maskedSettings = { ...settings, password: '******' };
  logInfo('Starting downloadPasskeyFromRenterd for file', { fileName });

  const url = buildRenterdURL(settings, fileName);
  logInfo('Constructed URL for downloading passkey', { url, settings: maskedSettings });

  const headers = createRenterdHeaders(settings);

  try {
    const response = await makeRequest(url, {
      method: 'GET',
      headers,
    });

    const data = await response.json();
    logInfo('Successfully downloaded and parsed passkey data', Object.keys(data));

    return data as StoredCredential;
  } catch (error) {
    logError(`Error downloading passkey ${fileName} from renterd`, error);
    throw error;
  }
}

export async function uploadPasskeyDirect(passkey: StoredCredential): Promise<{ success: boolean; message?: string; error?: string }> {
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

    logInfo('Passkey successfully uploaded to renterd', { uniqueId: passkey.uniqueId });
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
