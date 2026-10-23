/**
 * Chrome browser API wrapper.
 * Implements Promise-based WebExtensions API.
 */

import { logError } from '../logger';

const runtime = {
  sendMessage: (message: unknown): Promise<unknown> => {
    return new Promise((resolve) => {
      // Wrap Chrome's callback API with Promises
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          logError('[Chrome] runtime error', chrome.runtime.lastError);
          resolve({ error: chrome.runtime.lastError.message });
          return;
        }
        resolve(response);
      });
    });
  },

  getURL: (path: string): string => {
    // Direct passthrough to Chrome API
    return chrome.runtime.getURL(path);
  },

  getManifest: (): chrome.runtime.Manifest => {
    // Direct passthrough to Chrome API
    return chrome.runtime.getManifest();
  },

  onMessage: {
    addListener: (
      listener: (
        message: unknown,
        sender: chrome.runtime.MessageSender,
        sendResponse: (response?: unknown) => void,
      ) => void | Promise<unknown>,
    ): void => {
      chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        const result = listener(message, sender, sendResponse);

        if (result && typeof result.then === 'function') {
          result
            .then((response) => {
              sendResponse(response);
            })
            .catch((error) => {
              logError('[Chrome] Error in message listener', error);
              sendResponse({ error: error instanceof Error ? error.message : 'Unknown error' });
            });

          return true;
        }

        return false;
      });
    }
  },

  getBackgroundPage: (): Promise<Window> => {
    return new Promise((resolve, reject) => {
      chrome.runtime.getBackgroundPage((backgroundPage) => {
        if (chrome.runtime.lastError) {
          logError('[Chrome] Error getting background page', chrome.runtime.lastError);
          reject(new Error(chrome.runtime.lastError.message ?? 'Error getting background page'));
          return;
        }
        if (!backgroundPage) {
          reject(new Error('Background page not available'));
          return;
        }
        resolve(backgroundPage);
      });
    });
  }
};

const permissions = {
  request: (permissions: { origins: string[] }): Promise<boolean> => {
    return new Promise((resolve, reject) => {
      chrome.permissions.request(permissions, (granted) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message ?? 'Permission request failed'));
          return;
        }
        resolve(granted);
      });
    });
  },

  contains: (permissions: { origins: string[] }): Promise<boolean> => {
    return new Promise((resolve, reject) => {
      chrome.permissions.contains(permissions, (granted) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message ?? 'Permission check failed'));
          return;
        }
        resolve(granted);
      });
    });
  },

  getAll: (): Promise<{ origins?: string[] }> => {
    return new Promise((resolve, reject) => {
      chrome.permissions.getAll((permissions) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message ?? 'Permission check failed'));
          return;
        }
        resolve(permissions);
      });
    });
  },

  remove: (permissions: { origins: string[] }): Promise<boolean> => {
    return new Promise((resolve, reject) => {
      chrome.permissions.remove(permissions, (removed) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message ?? 'Permission removal failed'));
          return;
        }
        resolve(removed);
      });
    });
  },
};

const chromeAPI = {
  runtime,
  permissions,
};

export default chromeAPI;
