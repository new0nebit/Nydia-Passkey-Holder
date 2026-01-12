export function logDebug(message: string, data?: unknown) {
  if (data !== undefined) {
    console.debug(`[Debug] ${message}:`, data);
  } else {
    console.debug(`[Debug] ${message}`);
  }
}

export function logInfo(message: string, data?: unknown) {
  if (data !== undefined) {
    console.info(`[Info] ${message}:`, data);
  } else {
    console.info(`[Info] ${message}`);
  }
}

export function logWarn(message: string, data?: unknown) {
  if (data !== undefined) {
    console.warn(`[Warn] ${message}:`, data);
  } else {
    console.warn(`[Warn] ${message}`);
  }
}

export function logError(message: string, error?: unknown) {
  if (error !== undefined) {
    console.error(`[Error] ${message}`, error);
  } else {
    console.error(`[Error] ${message}`);
  }
}
