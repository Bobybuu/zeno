// src/context/AuthContext.tsx
import React, { createContext, useState, useContext, useEffect, ReactNode } from 'react';
import { authAPI } from '../services/api';

// Define types
interface User {
  id: number;
  email: string;
  username: string;
  first_name: string;
  last_name: string;
  phone_number: string;
  user_type: string;
  location: string;
  is_verified: boolean;
  email_verified: boolean;
  phone_verified: boolean;
  date_joined: string;
  cognito_user_id?: string;
}

interface AuthContextType {
  currentUser: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<{ success: boolean; data?: any; error?: any }>;
  register: (userData: any) => Promise<{ success: boolean; data?: any; error?: any }>;
  logout: () => Promise<void>;
  checkAuthentication: () => Promise<void>;
  updateUser: (userData: Partial<User>) => void;
  checkEmailVerification: (email: string) => Promise<{ is_verified: boolean }>;
  resendVerificationEmail: (email: string) => Promise<{ success: boolean; data?: any; error?: any }>;
  verifyEmail: (email: string, verification_code: string) => Promise<{ success: boolean; data?: any; error?: any }>;
  forgotPassword: (email: string) => Promise<{ success: boolean; data?: any; error?: any }>;
  resetPassword: (email: string, verification_code: string, new_password: string) => Promise<{ success: boolean; data?: any; error?: any }>;
  changePassword: (current_password: string, new_password: string) => Promise<{ success: boolean; data?: any; error?: any }>;
}

interface AuthProviderProps {
  children: ReactNode;
}

// Create context with default values
const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  // Check if user is logged in on app start
  useEffect(() => {
    checkAuthentication();
  }, []);

  const checkAuthentication = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const storedUser = localStorage.getItem('user');
      
      if (token && storedUser) {
        // Set user from localStorage immediately for better UX
        const user = JSON.parse(storedUser);
        setCurrentUser(user);
        
        // Then verify with backend if needed
        try {
          const response = await authAPI.checkAuth();
          if (response.data.authenticated) {
            setCurrentUser(response.data.user);
            localStorage.setItem('user', JSON.stringify(response.data.user));
          }
        } catch (error) {
          console.log('Auth check API call failed, using stored user:', error);
          // Continue with stored user if API fails
        }
      }
    } catch (error) {
      console.error('Authentication check failed:', error);
      // Clear invalid tokens
      clearAuthData();
      setCurrentUser(null);
    } finally {
      setLoading(false);
    }
  };

  const login = async (email: string, password: string) => {
    try {
      // Ensure email is lowercase
      const normalizedEmail = email.toLowerCase().trim();
      
      const response = await authAPI.login({ 
        email: normalizedEmail, 
        password 
      });
      
      if (response.data) {
        const { user, access, refresh } = response.data;
        
        // Check if email is verified
        if (!user.email_verified) {
          // Clear any stored tokens since email isn't verified
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          
          return { 
            success: false, 
            error: { 
              detail: 'Email not verified. Please check your email for verification instructions.' 
            } 
          };
        }
        
        // Store tokens and user data
        localStorage.setItem('access_token', access);
        localStorage.setItem('refresh_token', refresh);
        localStorage.setItem('user', JSON.stringify(user));
        
        setCurrentUser(user);
        return { success: true, data: response.data };
      }
      return { success: false, error: { message: 'No response data' } };
    } catch (error: any) {
      console.error('Login error:', error);
      return { 
        success: false, 
        error: error.response?.data || { message: 'Login failed' } 
      };
    }
  };

  const register = async (userData: any) => {
    try {
      // Ensure email is lowercase
      if (userData.email) {
        userData.email = userData.email.toLowerCase().trim();
      }
      
      const response = await authAPI.register(userData);
      
      if (response.data) {
        const { user, access, refresh } = response.data;
        
        // Note: With AWS Cognito, we don't get tokens immediately
        // because email needs to be verified first
        
        // Don't store tokens yet - user needs to verify email
        // Clear any temporary tokens
        localStorage.removeItem('temp_access_token');
        localStorage.removeItem('temp_refresh_token');
        localStorage.removeItem('temp_user');
        
        // Store user data temporarily to show verification message
        localStorage.setItem('pending_user_email', userData.email);
        
        return { 
          success: true, 
          data: response.data,
          requiresEmailVerification: true
        };
      }
      return { success: false, error: { message: 'No response data' } };
    } catch (error: any) {
      console.error('Registration error:', error);
      return { 
        success: false, 
        error: error.response?.data || { message: 'Registration failed' } 
      };
    }
  };

  const verifyEmail = async (email: string, verification_code: string) => {
    try {
      const response = await authAPI.verifyEmail({ 
        email: email.toLowerCase().trim(), 
        verification_code 
      });
      
      if (response.data?.success) {
        // Clear pending user email
        localStorage.removeItem('pending_user_email');
        
        return { success: true, data: response.data };
      }
      return { success: false, error: { message: 'Email verification failed' } };
    } catch (error: any) {
      console.error('Email verification error:', error);
      return { 
        success: false, 
        error: error.response?.data || { message: 'Email verification failed' } 
      };
    }
  };

  const resendVerificationEmail = async (email: string) => {
    try {
      const response = await authAPI.resendVerification({ 
        email: email.toLowerCase().trim() 
      });
      
      return { success: true, data: response.data };
    } catch (error: any) {
      console.error('Resend verification error:', error);
      return { 
        success: false, 
        error: error.response?.data || { message: 'Failed to resend verification email' } 
      };
    }
  };

  const checkEmailVerification = async (email: string) => {
    try {
      // This would typically be a custom endpoint
      // For now, we'll simulate with a check
      const response = await authAPI.getProfile();
      return { is_verified: response.data?.email_verified || false };
    } catch (error) {
      console.error('Check email verification error:', error);
      return { is_verified: false };
    }
  };

  const forgotPassword = async (email: string) => {
    try {
      const response = await authAPI.forgotPassword({ 
        email: email.toLowerCase().trim() 
      });
      
      return { success: true, data: response.data };
    } catch (error: any) {
      console.error('Forgot password error:', error);
      return { 
        success: false, 
        error: error.response?.data || { message: 'Password reset failed' } 
      };
    }
  };

  const resetPassword = async (email: string, verification_code: string, new_password: string) => {
    try {
      const response = await authAPI.resetPassword({
        email: email.toLowerCase().trim(),
        verification_code,
        new_password
      });
      
      return { success: true, data: response.data };
    } catch (error: any) {
      console.error('Reset password error:', error);
      return { 
        success: false, 
        error: error.response?.data || { message: 'Password reset failed' } 
      };
    }
  };

  const changePassword = async (current_password: string, new_password: string) => {
    try {
      const response = await authAPI.changePassword({
        current_password,
        new_password
      });
      
      return { success: true, data: response.data };
    } catch (error: any) {
      console.error('Change password error:', error);
      return { 
        success: false, 
        error: error.response?.data || { message: 'Password change failed' } 
      };
    }
  };

  const logout = async () => {
    try {
      // Optional: Call backend logout endpoint
      await authAPI.logout();
    } catch (error) {
      console.error('Logout API error:', error);
      // Continue with client-side logout even if API fails
    } finally {
      // Always clear local storage
      clearAuthData();
      setCurrentUser(null);
    }
  };

  const clearAuthData = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('user');
    localStorage.removeItem('temp_access_token');
    localStorage.removeItem('temp_refresh_token');
    localStorage.removeItem('temp_user');
    localStorage.removeItem('pending_user_email');
  };

  const updateUser = (userData: Partial<User>) => {
    setCurrentUser(prev => prev ? { ...prev, ...userData } : null);
    if (currentUser) {
      localStorage.setItem('user', JSON.stringify({ ...currentUser, ...userData }));
    }
  };

  const value: AuthContextType = {
    currentUser,
    loading,
    login,
    register,
    logout,
    checkAuthentication,
    updateUser,
    checkEmailVerification,
    resendVerificationEmail,
    verifyEmail,
    forgotPassword,
    resetPassword,
    changePassword,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};