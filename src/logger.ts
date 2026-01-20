export function logInfo(message: string, data?: unknown) {
  if (data !== undefined) {
    console.info(`[Info] ${message}:`, data);
  } else {
    console.info(`[Info] ${message}`);
  }
}

export function logError(message: string, error?: unknown) {
  if (error !== undefined) {
    console.error(`[Error] ${message}`, error);
  } else {
    console.error(`[Error] ${message}`);
  }
}
