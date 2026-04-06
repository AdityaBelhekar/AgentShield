interface Window {
  agentshield: {
    getBackendPort: () => Promise<number>;
    getBackendLogs: () => Promise<string[]>;
    minimizeWindow: () => void;
    maximizeWindow: () => void;
    closeWindow: () => void;
    onBackendStatus: (cb: (event: any, status: boolean) => void) => () => void;
    platform: string;
  }
}
