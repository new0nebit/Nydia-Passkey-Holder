import { Account, WebAuthnOperationType } from '../types';

export const PopupMessage = {
  Init: 'nydia-popup-init',
  Action: 'nydia-popup-action',
  Close: 'nydia-popup-close',
  Error: 'nydia-popup-error',
  Resize: 'nydia-popup-resize',
} as const;

export type PopupInitPayload = {
  operationType: WebAuthnOperationType;
  rpId: string;
  userName?: string;
  accounts?: Account[];
};

export type PopupInitMessage = {
  type: typeof PopupMessage.Init;
  sessionId: string;
  payload: PopupInitPayload;
};

type PopupActionMessage = {
  type: typeof PopupMessage.Action;
  sessionId: string;
  selectedUniqueId?: string;
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

export type PopupResizeMessage = {
  type: typeof PopupMessage.Resize;
  sessionId: string;
  width: number;
  height: number;
};

export type PopupFrameMessage = PopupActionMessage | PopupCloseMessage | PopupResizeMessage;
