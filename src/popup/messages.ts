import { Account, WebAuthnOperationType } from '../types';

export const PopupMessage = {
  Init: 'nydia-popup-init',
  Action: 'nydia-popup-action',
  Close: 'nydia-popup-close',
  Error: 'nydia-popup-error',
} as const;

export type PopupInitPayload = {
  operationType: WebAuthnOperationType;
  rpId: string;
  userName?: string;
  accounts?: Account[];
  hostIsDark?: boolean;
};

export type PopupInitMessage = {
  type: typeof PopupMessage.Init;
  sessionId: string;
  payload: PopupInitPayload;
};

type PopupActionMessage = {
  type: typeof PopupMessage.Action;
  sessionId: string;
  selectedCredentialId?: string;
};

type PopupCloseMessage = {
  type: typeof PopupMessage.Close;
  sessionId: string;
};

export type PopupErrorMessage = {
  type: typeof PopupMessage.Error;
  sessionId: string;
  message: string;
};

export type PopupFrameMessage = PopupActionMessage | PopupCloseMessage;
