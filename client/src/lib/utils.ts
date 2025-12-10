import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}


// lib/utils.ts
export const calculateDistance = (
  lat1: number,
  lng1: number,
  lat2: number,
  lng2: number
): string => {
  // Haversine formula for accurate distance calculation
  const R = 6371; // Earth's radius in km
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLng = (lng2 - lng1) * Math.PI / 180;
  const a = 
    Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
    Math.sin(dLng/2) * Math.sin(dLng/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  const distance = R * c;
  
  if (distance < 1) {
    return `${Math.round(distance * 1000)}m away`;
  } else if (distance < 10) {
    return `${distance.toFixed(1)}km away`;
  }
  return `${Math.round(distance)}km away`;
};

export const formatPrice = (price: number): string => {
  return `KSh ${price?.toLocaleString('en-KE') || '0'}`;
};

// Helper to get the best image for a product
export const getBestProductImage = (product: any) => {
  if (!product.images || product.images.length === 0) {
    return null;
  }
  
  // Prefer primary image, otherwise first image
  const primaryImage = product.images.find((img: any) => img.is_primary);
  return primaryImage || product.images[0];
};

// Helper to format image URL
export const formatImageUrl = (imagePath: string): string | null => {
  if (!imagePath) return null;
  
  if (imagePath.startsWith('http')) {
    return imagePath;
  }
  
  // Handle different image path formats
  if (imagePath.startsWith('/media/') || imagePath.startsWith('/static/')) {
    return `https://api.zenoservices.co.ke/${imagePath}`;
  }
  
  if (imagePath.startsWith('media/') || imagePath.startsWith('static/')) {
    return `https://api.zenoservices.co.ke/${imagePath}`;
  }

  return `https://api.zenoservices.co.ke/media/${imagePath}`;
};