// src/components/BackendStatus.tsx
import { useState, useEffect } from 'react';
import { healthAPI } from '@/services/api';
import { Badge } from '@/components/ui/badge';
import { Wifi, WifiOff } from 'lucide-react';

export const BackendStatus = () => {
  const [isOnline, setIsOnline] = useState<boolean | null>(null);

  useEffect(() => {
    const checkBackend = async () => {
      try {
        await healthAPI.checkBackendHealth();
        setIsOnline(true);
      } catch (error) {
        setIsOnline(false);
      }
    };

    checkBackend();
    const interval = setInterval(checkBackend, 30000); // Check every 30 seconds

    return () => clearInterval(interval);
  }, []);

  if (isOnline === null) return null;

  return (
    <Badge 
      variant={isOnline ? "default" : "secondary"} 
      className="text-xs"
    >
      {isOnline ? (
        <>
          <Wifi className="h-3 w-3 mr-1" />
          Online
        </>
      ) : (
        <>
          <WifiOff className="h-3 w-3 mr-1" />
          Offline
        </>
      )}
    </Badge>
  );
};