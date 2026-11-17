import type { User } from './types';

const KEY = 'tracevault.session';

interface Session {
  token: string;
  user: User;
}

let current: Session | null = (() => {
  try {
    const raw = sessionStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as Session) : null;
  } catch {
    return null;
  }
})();

const listeners = new Set<() => void>();

export const auth = {
  get session(): Session | null {
    return current;
  },
  get token(): string | null {
    return current?.token ?? null;
  },
  set(session: Session | null) {
    current = session;
    try {
      if (session) sessionStorage.setItem(KEY, JSON.stringify(session));
      else sessionStorage.removeItem(KEY);
    } catch {
      /* storage unavailable: memory only */
    }
    listeners.forEach((l) => l());
  },
  subscribe(fn: () => void) {
    listeners.add(fn);
    return () => {
      listeners.delete(fn);
    };
  },
};
