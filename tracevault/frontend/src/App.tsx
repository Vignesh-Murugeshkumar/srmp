import React, { useEffect, useState } from 'react';
import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { auth } from './api/auth';
import { AppShell } from './components/AppShell';
import { LoginView } from './components/LoginView';
import { WorkstationProvider } from './components/WorkstationContext';
import { ArtifactExplorerScreen } from './screens/ArtifactExplorerScreen';
import { CommandCenterScreen } from './screens/CommandCenterScreen';
import { EvidenceUniverseScreen } from './screens/EvidenceUniverseScreen';
import { IncidentReconstructionScreen } from './screens/IncidentReconstructionScreen';
import { TemporalStudioScreen } from './screens/TemporalStudioScreen';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

export const App: React.FC = () => {
  const [hasSession, setHasSession] = useState<boolean>(Boolean(auth.session));

  useEffect(() => {
    return auth.subscribe(() => {
      setHasSession(Boolean(auth.session));
    });
  }, []);

  if (!hasSession) {
    return <LoginView />;
  }

  return (
    <QueryClientProvider client={queryClient}>
      <WorkstationProvider>
        <BrowserRouter>
          <Routes>
            <Route element={<AppShell />}>
              <Route index element={<CommandCenterScreen />} />
              <Route path="universe" element={<EvidenceUniverseScreen />} />
              <Route path="temporal" element={<TemporalStudioScreen />} />
              <Route path="artifacts" element={<ArtifactExplorerScreen />} />
              <Route path="incidents" element={<IncidentReconstructionScreen />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </WorkstationProvider>
    </QueryClientProvider>
  );
};
