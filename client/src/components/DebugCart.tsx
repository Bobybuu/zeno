// src/components/DebugCart.tsx (temporary)
import { useEffect } from 'react';
import { useCart } from '@/context/CartContext';

export const DebugCart = () => {
  const { cart, loading } = useCart();
  
  useEffect(() => {
    console.log('🔍 DEBUG - Cart state:', { cart, loading });
    console.log('🔍 DEBUG - localStorage cart:', localStorage.getItem('gaslink_cart'));
  }, [cart, loading]);
  
  return null; // This component doesn't render anything
};