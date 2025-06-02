/**
 * Firefox browser API wrapper
 * This is a simple re-export of the native Firefox browser API
 */

// Check for the global browser object
if (typeof browser === 'undefined') {
  console.error('Firefox browser API is not available');
}

// Simply export the global browser object
const firefoxAPI = browser;
export default firefoxAPI;