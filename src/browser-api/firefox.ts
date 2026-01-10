/**
 * Firefox browser API wrapper
 * This is a simple re-export of the native Firefox browser API
 */

// Get Firefox's global browser API
const firefoxAPI = (globalThis as { browser?: unknown }).browser;
export default firefoxAPI;
