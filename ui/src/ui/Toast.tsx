import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';
import Snackbar from '@mui/material/Snackbar';

// One small message at the bottom, for what a button did ("Copied"). In the
// demo the copy message also says the command is an example.

const ToastContext = createContext<(message: string) => void>(() => {});

export function useToast() {
  return useContext(ToastContext);
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [message, setMessage] = useState<string | null>(null);
  const show = useCallback((m: string) => setMessage(m), []);
  const value = useMemo(() => show, [show]);
  return (
    <ToastContext.Provider value={value}>
      {children}
      <Snackbar
        open={message !== null}
        onClose={(_e, reason) => reason !== 'clickaway' && setMessage(null)}
        autoHideDuration={4200}
        message={message}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
        sx={{ bottom: { xs: 88, lg: 24 } }}
        slotProps={{ content: { role: 'status', 'aria-live': 'polite' } as object }}
      />
    </ToastContext.Provider>
  );
}
