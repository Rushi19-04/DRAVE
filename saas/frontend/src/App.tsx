import React from 'react';
import { Dashboard } from './components/Dashboard';
import { SignedIn, SignedOut, SignIn, UserButton } from '@clerk/clerk-react';

function App() {
  return (
    <div className="min-h-screen bg-background">
      <header className="absolute top-4 right-8 z-50">
        <SignedIn>
          <UserButton />
        </SignedIn>
      </header>
      
      <SignedIn>
        <Dashboard />
      </SignedIn>
      
      <SignedOut>
        <div className="flex items-center justify-center min-h-screen">
          <SignIn />
        </div>
      </SignedOut>
    </div>
  );
}

export default App;
