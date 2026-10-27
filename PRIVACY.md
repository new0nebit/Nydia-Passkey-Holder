# Privacy Policy — Nydia: Passkey Holder

Last updated: October 26, 2026

This policy explains how Nydia handles your information in Chrome, Firefox, and Safari. It will be updated when Nydia's privacy practices change.

## Summary

- **No Nydia account.** You don't need a Nydia account to use the extension.
- **Local storage.** Your passkeys are encrypted and stored on your device.
- **No ads or analytics.** Nydia doesn't automatically send usage statistics or crash reports.
- **No data selling.** Your information isn't sold or used for targeted advertising.
- **Sia backups.** When you back up or sync, encrypted copies go to the Sia network through a server you choose.

Nydia communicates only with websites when you create a passkey or sign in, with your chosen server for backups, and, if you turn on website icons, with Google. The sections below explain what each of them receives.

## What Nydia stores on your device

Nydia saves the following in your browser's local extension storage:

- Your passkeys, including the website, username, and creation date for each.
- An encryption key, so you don't need to enter your recovery phrase each time you use the extension.
- Settings for renterd, the software used to back up to Sia: server address, port, connection type, password, and bucket name.
- Whether you've completed initial setup and which passkeys have been backed up.
- Whether website icons are on and, if they are, the icons Nydia has saved.

Nydia encrypts your passkeys, their details, your renterd settings, including the server password, and saved website icons with AES-256-GCM.

## Recovery phrase

During setup, Nydia generates a 12-word recovery phrase on your device or lets you enter an existing Nydia phrase. It creates your encryption key from the phrase locally and stores the key, not the phrase itself. Nydia doesn't send your recovery phrase or encryption key outside your device.

To restore backed-up passkeys on a new device or after clearing the extension's storage, you need your recovery phrase, the encrypted backup, and access to the renterd server and bucket where you saved it. Keep your phrase somewhere safe.

## Using passkeys on websites

To create a passkey or find the right one for signing in, Nydia reads the website's passkey request. The request can include the site's address, your username, identifiers for your account and passkeys, and data used to verify the sign-in. Nydia works on websites where you've allowed the extension to run.

When you create a passkey, Nydia gives the website a public key and passkey identifier. When you sign in, it returns a signed response that the website can verify, along with the passkey identifier and the account identifier originally supplied by that website. These are standard WebAuthn responses and never include your private key.

The website can send these responses to its server and keep them under its own privacy policy. Deleting a passkey in Nydia doesn't delete your account or remove the passkey's registration on that website.

## Sia backups

Backups are optional. Nydia contacts your renterd server only when you:

- choose **Test Connection**, which checks your saved settings;
- choose **Backup to Sia**, which uploads an encrypted copy of the selected passkey;
- choose **Sync Passkeys**, which uploads passkeys that haven't been backed up yet and downloads backups from your server.

Passkeys are encrypted before they leave your device. Your server stores them as encrypted files with random-looking names and never receives your recovery phrase or encryption key. Like any server, it can see your IP address and when and how much data you transfer. If someone else runs the server, their privacy practices apply, including how long they keep backups and logs.

Nydia tries HTTPS when checking your server connection and uses HTTP if the check fails. Your passkeys remain encrypted either way, but HTTP doesn't protect your server password in transit. For servers outside your local network, use HTTPS.

## Website icons

Website icons are optional and off by default. You can turn them on or off at any time with **Show website icons** in Nydia's Settings.

When icons are on, Nydia shows an icon next to each saved passkey. It uses icons already saved on your device and requests missing ones from Google's favicon service when the passkey list is displayed or refreshed. The request includes the site's domain, sometimes with a subdomain. Google also receives your IP address and the request headers sent by your browser.

These requests don't include usernames, passkey records, private keys, or your recovery phrase. If an icon can't be loaded, Nydia shows a local globe icon.

Saved icons are encrypted on your device and aren't included in Sia backups.

When icons are off, Nydia sends no icon requests to Google and deletes the icons it has saved. Limiting Nydia's website access in your browser doesn't affect icon requests; only this setting does.

Google's handling and retention of this information are covered by its [Privacy Policy](https://policies.google.com/privacy).

## Getting help

When you contact support by email, your address and message are used to answer your request. The conversation, including replies, is deleted within 70 days after it's resolved or closed, or earlier if you ask. Support email is handled through iCloud Mail under [Apple's Privacy Policy](https://www.apple.com/legal/privacy/).

You can also report problems through [GitHub Issues](https://github.com/new0nebit/Nydia-Passkey-Holder/issues). Your GitHub username, message, and attachments are public there, even after an issue is closed. GitHub's handling of information is covered by its [Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement). Use email for anything you don't want to post publicly.

## Keeping and deleting your information

Your passkeys, encryption key, and settings stay on your device until you clear the extension's storage. You can also delete individual passkeys. Deleting a local passkey doesn't delete its backup, which **Sync Passkeys** can download again. To delete backups, use your renterd administration tools or contact the server operator.

## Contact

Nydia is developed by Oleh Nypadymka. For questions about Nydia's privacy practices, write to [hello@nydia.app](mailto:hello@nydia.app).
