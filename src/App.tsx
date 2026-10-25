import React from 'react';
import { CaseProvider } from './context/CaseContext.tsx';
import { Shell } from './components/layout/Shell.tsx';

export default function App() {
  return (
    <CaseProvider>
      <Shell />
    </CaseProvider>
  );
}
