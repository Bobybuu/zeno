import React, { ReactNode } from 'react';
import { useCart } from '@/context/CartContext';

interface MainLayoutProps {
  children: ReactNode;
}

const MainLayout: React.FC<MainLayoutProps> = ({ children }) => {
  
  const { cartItemCount } = useCart();

  // Your layout implementation
  return (
    <div className="main-layout">
      {/* You can use cartItemCount here in your layout */}
      {children}
    </div>
  );
};

export default MainLayout;