import { create } from 'zustand';

export const useNavigationStore = create<{
  currentView: string;
  navigate: (view: string) => void;
}>((set) => ({
  currentView: 'DASHBOARD',
  navigate: (view) => set({ currentView: view })
}));

export const useBackendStore = create<{
  port: number;
  status: 'online' | 'offline' | 'starting';
  logs: string[];
  setPort: (port: number) => void;
  setStatus: (status: 'online' | 'offline' | 'starting') => void;
  appendLog: (log: string) => void;
}>((set) => ({
  port: 8765,
  status: 'starting',
  logs: [],
  setPort: (port) => set({ port }),
  setStatus: (status) => set({ status }),
  appendLog: (log) => set((state) => ({ logs: [...state.logs, log].slice(-500) }))
}));

export const useCommandPaletteStore = create<{
  isOpen: boolean;
  query: string;
  open: () => void;
  close: () => void;
  setQuery: (q: string) => void;
}>((set) => ({
  isOpen: false,
  query: '',
  open: () => set({ isOpen: true }),
  close: () => set({ isOpen: false, query: '' }),
  setQuery: (query) => set({ query })
}));
