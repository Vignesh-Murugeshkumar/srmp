import React, { createContext, useContext, useState } from 'react';
import type { Investigation } from '../api/types';

interface WorkstationContextValue {
  activeInvestigationId: string | null;
  setActiveInvestigationId: (id: string | null) => void;
  activeInvestigation: Investigation | null;
  setActiveInvestigation: (inv: Investigation | null) => void;
  focusedEntityId: string | null;
  setFocusedEntityId: (id: string | null) => void;
  timeTravelCursor: string | null;
  setTimeTravelCursor: (iso: string | null) => void;
}

const WorkstationContext = createContext<WorkstationContextValue | null>(null);

export const WorkstationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [activeInvestigationId, setActiveInvestigationId] = useState<string | null>(null);
  const [activeInvestigation, setActiveInvestigation] = useState<Investigation | null>(null);
  const [focusedEntityId, setFocusedEntityId] = useState<string | null>(null);
  const [timeTravelCursor, setTimeTravelCursor] = useState<string | null>(null);

  return (
    <WorkstationContext.Provider
      value={{
        activeInvestigationId,
        setActiveInvestigationId,
        activeInvestigation,
        setActiveInvestigation,
        focusedEntityId,
        setFocusedEntityId,
        timeTravelCursor,
        setTimeTravelCursor,
      }}
    >
      {children}
    </WorkstationContext.Provider>
  );
};

export function useWorkstation(): WorkstationContextValue {
  const ctx = useContext(WorkstationContext);
  if (!ctx) throw new Error('useWorkstation must be used inside WorkstationProvider');
  return ctx;
}
