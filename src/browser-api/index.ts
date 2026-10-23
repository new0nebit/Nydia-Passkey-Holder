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
  getManifest: () => { content_scripts?: { matches?: string[] }[]; host_permissions?: string[] };
  getBackgroundPage?: () => Promise<Window>;
};

export type BrowserAPI = {
  runtime: Runtime;
  permissions: {
    request: (permissions: { origins: string[] }) => Promise<boolean>;
    contains: (permissions: { origins: string[] }) => Promise<boolean>;
    getAll: () => Promise<{ origins?: string[] }>;
    remove: (permissions: { origins: string[] }) => Promise<boolean>;
  };
};

const resolvedBrowser: BrowserAPI =
  (firefoxAPI as BrowserAPI) ?? chromeAPI;

export default resolvedBrowser;
