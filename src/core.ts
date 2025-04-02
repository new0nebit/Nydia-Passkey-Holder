import './authenticator';
import './algorithms';
import './store';
import './types';
import './logger';
import { initializeAuthenticator } from './authenticator';

// Initializes the WebAuthn authenticator when the core script is loaded.
initializeAuthenticator();
