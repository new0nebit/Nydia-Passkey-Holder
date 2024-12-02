import './authenticator';
import './algorithms';
import './store';
import './types';
import './popup';
import './logger';

import { initializeAuthenticator } from './authenticator';

/**
 * Initializes the WebAuthn authenticator when the core script is loaded.
 */
initializeAuthenticator();

/* ================================================
   Event Listeners
=============================================== */

/**
 * Listens for custom 'webauthn-data' events dispatched from the web page.
 * Forwards the data to the background script and handles the response.
 */
window.addEventListener('webauthn-data', (event: any) => {
  // Send data to the background script
  chrome.runtime.sendMessage(event.detail, (response) => {
    if (chrome.runtime.lastError) {
      console.error(
        'Error sending message to background script:',
        chrome.runtime.lastError
      );
    } else {
      // Handle the response from the background script
      console.log('Received response from background script:', response);

      // Dispatch an event back to the page with the response
      const responseEvent = new CustomEvent('webauthn-response', {
        detail: response,
      });
      window.dispatchEvent(responseEvent);
    }
  });
});

/**
 * Listens for messages from the background script and forwards them to the web page.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'webauthn-response') {
    // Dispatch an event to the page with the response data
    const responseEvent = new CustomEvent('webauthn-response', {
      detail: message.data,
    });
    window.dispatchEvent(responseEvent);
    sendResponse({ status: 'success' });
  }
  // Handle additional message types if necessary

  return true; // Indicates that sendResponse will be called asynchronously
});
