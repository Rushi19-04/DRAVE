import { Dashboard } from './components/Dashboard';
import { SignedIn, SignedOut, SignIn } from '@clerk/clerk-react';

function App() {
  return (
    <div className="min-h-screen bg-background">
      
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
