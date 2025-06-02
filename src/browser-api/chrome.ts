/**
 * Chrome browser API wrapper
 * Implements Promise-based API compatible with Firefox's browser API
 */

const runtime = {
  sendMessage: (message: any): Promise<any> => {
    return new Promise((resolve) => {
      // Wrap Chrome callback API in Promise for Firefox compatibility
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          console.error('Chrome runtime error:', chrome.runtime.lastError);
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

  onMessage: {
    addListener: (listener: (message: any, sender: any, sendResponse: any) => void | Promise<any>): void => {
      chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        const result = listener(message, sender, sendResponse);
        
        if (result && typeof result.then === 'function') {
          result.then((response) => {
            sendResponse(response);
          }).catch((error) => {
            console.error('Error in message listener:', error);
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
          console.error('Error getting background page:', chrome.runtime.lastError);
          reject(chrome.runtime.lastError);
          return;
        }
        resolve(backgroundPage);
      });
    });
  }
};

const chromeAPI = {
  runtime
};

export default chromeAPI;