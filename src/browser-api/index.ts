import chromeAPI from './chrome';
import firefoxAPI from './firefox';

type SendMessage = (message: unknown) => Promise<unknown>;

type Runtime = {
  id?: string;
  sendMessage: SendMessage;
  onMessage: {
    addListener: (
      listener: (
        message: unknown,
        sender: unknown,
        sendResponse: (response?: unknown) => void,
      ) => void | Promise<unknown>,
    ) => void;
  };
  getURL: (path: string) => string;
  getBackgroundPage?: () => Promise<Window>;
};

export type BrowserAPI = {
  runtime: Runtime;
};

const resolvedBrowser: BrowserAPI =
  (firefoxAPI as BrowserAPI) ?? (chromeAPI as BrowserAPI);

export default resolvedBrowser;
