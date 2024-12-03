import { RenterdSettings } from './types';

export async function uploadPasskeyToRenterd(
  fileContent: Blob | null,
  fileName: string,
  settings: RenterdSettings,
  testConnection = false
): Promise<void> {
  const url = `http://${settings.serverAddress}:${settings.serverPort}/api/worker/objects/${fileName}?bucket=${settings.bucketName}`;
  const headers: HeadersInit = {
    'Content-Type': 'application/octet-stream',
    'Authorization': 'Basic ' + btoa(`root:${settings.password}`),
  };

  try {
    const response = await fetch(url, {
      method: 'PUT',
      headers,
      body: testConnection ? undefined : fileContent,
    });

    if (!response.ok) {
      throw new Error(`Failed to upload to renterd: ${response.statusText}`);
    }
  } catch (error) {
    console.error('Error uploading to renterd:', error);
    throw error;
  }
}
