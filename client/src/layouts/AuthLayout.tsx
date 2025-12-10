import React, { ReactNode } from 'react';

interface AuthLayoutProps {
  children: ReactNode;
}

const AuthLayout: React.FC<AuthLayoutProps> = ({ children }) => {
  // Your layout implementation
  return (
    <div className="auth-layout">
      {children}
    </div>
  );
};

export default AuthLayout;