/**
 * Safari browser API wrapper
 * This is a simple re-export of the native Safari browser API
 */

// Get Safari's global browser API
const safariAPI = (globalThis as { browser?: unknown }).browser;
export default safariAPI;
