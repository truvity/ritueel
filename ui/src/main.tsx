import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import CssBaseline from '@mui/material/CssBaseline';
import GlobalStyles from '@mui/material/GlobalStyles';
import { StyledEngineProvider, ThemeProvider } from '@mui/material/styles';
import { App } from './App';
import { theme } from './theme';
import './index.css';

// MUI emits into @layer mui; Tailwind utilities come after it and win without !important.
const layerOrder = <GlobalStyles styles="@layer theme, base, mui, components, utilities;" />;

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <StyledEngineProvider enableCssLayer>
      {layerOrder}
      <ThemeProvider theme={theme} defaultMode="system" modeStorageKey="ritueel-mode" colorSchemeStorageKey="ritueel-scheme">
        <CssBaseline enableColorScheme />
        <App />
      </ThemeProvider>
    </StyledEngineProvider>
  </StrictMode>,
);
