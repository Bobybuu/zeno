import React from 'react';
import { Wifi, WifiOff } from 'lucide-react';
import { useNetwork } from '@/hooks/useNetwork';

export const OfflineIndicator: React.FC = () => {
  const { isOnline } = useNetwork();

  if (isOnline) return null;

  return (
    <div className="fixed top-0 left-0 right-0 bg-yellow-500 text-white text-center py-2 text-sm z-50 animate-pulse">
      <div className="flex items-center justify-center gap-2">
        <WifiOff className="h-4 w-4" />
        <span>You are currently offline. Some features may be limited.</span>
      </div>
    </div>
  );
};