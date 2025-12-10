import React, { useState, useEffect } from 'react';
import { Download, X, Smartphone, CheckCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

interface BeforeInstallPromptEvent extends Event {
  prompt(): Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed' }>;
}

export const PWAInstallButton: React.FC = () => {
  const [deferredPrompt, setDeferredPrompt] = useState<BeforeInstallPromptEvent | null>(null);
  const [isInstallable, setIsInstallable] = useState(false);
  const [isInstalled, setIsInstalled] = useState(false);
  const [showPrompt, setShowPrompt] = useState(false);
  const [isInstalling, setIsInstalling] = useState(false);

  useEffect(() => {
    const handleBeforeInstallPrompt = (e: BeforeInstallPromptEvent) => {
      e.preventDefault();
      setDeferredPrompt(e);
      setIsInstallable(true);
      
      // Auto-show prompt after 5 seconds if not dismissed before
      const wasDismissed = localStorage.getItem('zeno-pwa-prompt-dismissed');
      if (!wasDismissed) {
        setTimeout(() => {
          setShowPrompt(true);
        }, 5000);
      }
    };

    const handleAppInstalled = () => {
      console.log('ZENO PWA was installed successfully');
      setIsInstalled(true);
      setIsInstallable(false);
      setShowPrompt(false);
      setDeferredPrompt(null);
      
      // Track installation
      localStorage.setItem('zeno-pwa-installed', 'true');
    };

    // Check if app is already installed
    const checkIfInstalled = () => {
      if (window.matchMedia('(display-mode: standalone)').matches) {
        setIsInstalled(true);
        setIsInstallable(false);
      }
      
      // Check localStorage
      if (localStorage.getItem('zeno-pwa-installed')) {
        setIsInstalled(true);
      }
    };

    checkIfInstalled();

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt as EventListener);
    window.addEventListener('appinstalled', handleAppInstalled);

    return () => {
      window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt as EventListener);
      window.removeEventListener('appinstalled', handleAppInstalled);
    };
  }, []);

  const handleInstall = async () => {
    if (!deferredPrompt) return;

    try {
      setIsInstalling(true);
      deferredPrompt.prompt();
      
      const { outcome } = await deferredPrompt.userChoice;
      
      if (outcome === 'accepted') {
        console.log('User accepted the install prompt');
        setIsInstalled(true);
      } else {
        console.log('User dismissed the install prompt');
      }
      
      setDeferredPrompt(null);
      setIsInstallable(false);
      setShowPrompt(false);
      
    } catch (error) {
      console.error('Error installing PWA:', error);
    } finally {
      setIsInstalling(false);
    }
  };

  const handleDismissPrompt = () => {
    setShowPrompt(false);
    // Remember dismissal for 7 days
    localStorage.setItem('zeno-pwa-prompt-dismissed', 'true');
    setTimeout(() => {
      localStorage.removeItem('zeno-pwa-prompt-dismissed');
    }, 7 * 24 * 60 * 60 * 1000); // 7 days
  };

  const handleDismissPermanently = () => {
    setShowPrompt(false);
    setIsInstallable(false);
    localStorage.setItem('zeno-pwa-prompt-dismissed', 'true');
  };

  // Don't show anything if installed or not installable
  

  return (
    <>
      {/* Floating Install Prompt */}
      {showPrompt && (
        <div className="fixed inset-0 z-50 flex items-end justify-center p-4 sm:items-center sm:p-0">
          {/* Backdrop */}
          <div 
            className="fixed inset-0 bg-black/50 transition-opacity"
            onClick={handleDismissPrompt}
          />
          
          {/* Prompt Card */}
          <Card className="relative w-full max-w-md p-6 bg-background shadow-lg rounded-lg border-2 border-primary/20">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10">
                  <Smartphone className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <h3 className="font-semibold text-lg">Install ZENO App</h3>
                  <p className="text-sm text-muted-foreground">
                    Get the best experience
                  </p>
                </div>
              </div>
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                onClick={handleDismissPrompt}
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
            
            <div className="space-y-3 mb-6">
              <div className="flex items-center gap-2 text-sm">
                <div className="h-2 w-2 rounded-full bg-primary" />
                <span>Fast loading & offline access</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <div className="h-2 w-2 rounded-full bg-primary" />
                <span>Quick access from home screen</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <div className="h-2 w-2 rounded-full bg-primary" />
                <span>Push notifications for orders</span>
              </div>
            </div>
            
            <div className="flex gap-3">
              <Button
                onClick={handleInstall}
                disabled={isInstalling}
                className="flex-1"
              >
                {isInstalling ? (
                  <>
                    <div className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent mr-2" />
                    Installing...
                  </>
                ) : (
                  <>
                    <Download className="h-4 w-4 mr-2" />
                    Install App
                  </>
                )}
              </Button>
              <Button
                variant="outline"
                onClick={handleDismissPermanently}
              >
                No Thanks
              </Button>
            </div>
            
            <p className="text-xs text-muted-foreground text-center mt-3">
              Takes just a few seconds
            </p>
          </Card>
        </div>
      )}

      {/* Header Install Button */}
      {isInstallable && !showPrompt && (
        <Button
          variant="outline"
          size="sm"
          onClick={() => setShowPrompt(true)}
          className="hidden sm:flex items-center gap-2"
        >
          <Download className="h-4 w-4" />
          Install App
        </Button>
      )}
    </>
  );
};