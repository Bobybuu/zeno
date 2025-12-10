// src/pages/VerifyEmail.tsx
import { useState, useEffect, useRef } from "react";
import { useLocation, useNavigate, Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Mail, Shield, RefreshCw, ArrowLeft, CheckCircle, XCircle } from "lucide-react";
import { motion } from "framer-motion";
import { toast } from "sonner";
import { useAuth } from "@/context/AuthContext";

const VerifyEmail = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { verifyEmail, resendVerificationEmail } = useAuth();
  
  const [email, setEmail] = useState<string>("");
  const [verificationCode, setVerificationCode] = useState<string[]>(["", "", "", "", "", ""]);
  const [isLoading, setIsLoading] = useState(false);
  const [isResending, setIsResending] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0);
  const [verificationStatus, setVerificationStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState<string>("");
  
  const inputRefs = useRef<(HTMLInputElement | null)[]>([]);

  useEffect(() => {
    // Get email from location state or localStorage
    const stateEmail = location.state?.email;
    const storedEmail = localStorage.getItem('pending_user_email');
    
    if (stateEmail) {
      setEmail(stateEmail);
    } else if (storedEmail) {
      setEmail(storedEmail);
    } else {
      // No email found, redirect to check-email
      navigate("/check-email");
    }
  }, [location, navigate]);

  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (resendCooldown > 0) {
      timer = setTimeout(() => setResendCooldown(resendCooldown - 1), 1000);
    }
    return () => clearTimeout(timer);
  }, [resendCooldown]);

  const handleCodeChange = (index: number, value: string) => {
    // Only allow numbers
    const numericValue = value.replace(/\D/g, '');
    
    if (numericValue.length > 1) {
      // Handle paste: split the pasted value across inputs
      const pastedDigits = numericValue.split('').slice(0, 6);
      const newCode = [...verificationCode];
      
      pastedDigits.forEach((digit, i) => {
        if (i < 6) newCode[i] = digit;
      });
      
      setVerificationCode(newCode);
      
      // Focus the next empty input or submit if all filled
      const emptyIndex = newCode.findIndex((digit, i) => i >= index && digit === "");
      if (emptyIndex !== -1) {
        inputRefs.current[emptyIndex]?.focus();
      } else {
        inputRefs.current[5]?.blur();
      }
    } else {
      const newCode = [...verificationCode];
      newCode[index] = numericValue;
      setVerificationCode(newCode);
      
      // Auto-focus next input if value entered
      if (numericValue && index < 5) {
        inputRefs.current[index + 1]?.focus();
      }
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !verificationCode[index] && index > 0) {
      // Move to previous input on backspace if current is empty
      inputRefs.current[index - 1]?.focus();
    }
  };

  const handleVerifyEmail = async () => {
    const code = verificationCode.join('');
    
    if (code.length !== 6) {
      toast.error("Please enter the complete 6-digit verification code");
      return;
    }

    if (!email) {
      toast.error("Email not found. Please try again.");
      return;
    }

    setIsLoading(true);
    setVerificationStatus('idle');
    setErrorMessage("");

    try {
      const result = await verifyEmail(email, code);
      
      if (result.success) {
        setVerificationStatus('success');
        toast.success("Email verified successfully!");
        
        // Clear pending email from localStorage
        localStorage.removeItem('pending_user_email');
        
        // Redirect to login after 2 seconds
        setTimeout(() => {
          navigate("/login", { 
            state: { 
              message: "Email verified successfully! You can now log in." 
            } 
          });
        }, 2000);
      } else {
        setVerificationStatus('error');
        setErrorMessage(result.error?.detail || "Invalid verification code");
        toast.error(result.error?.detail || "Verification failed");
      }
    } catch (error) {
      setVerificationStatus('error');
      setErrorMessage("An unexpected error occurred");
      toast.error("An unexpected error occurred");
    } finally {
      setIsLoading(false);
    }
  };

  const handleResendVerification = async () => {
    if (!email || resendCooldown > 0) return;
    
    setIsResending(true);
    try {
      const result = await resendVerificationEmail(email);
      
      if (result.success) {
        toast.success("Verification code sent successfully!");
        setResendCooldown(60); // 60 seconds cooldown
        
        // Clear and refocus inputs
        setVerificationCode(["", "", "", "", "", ""]);
        inputRefs.current[0]?.focus();
      } else {
        toast.error(result.error?.message || "Failed to resend verification code");
      }
    } catch (error) {
      toast.error("An unexpected error occurred");
    } finally {
      setIsResending(false);
    }
  };

  const handleGoBack = () => {
    navigate("/check-email");
  };

  const handleGoToLogin = () => {
    navigate("/login");
  };

  const handleClearAll = () => {
    setVerificationCode(["", "", "", "", "", ""]);
    inputRefs.current[0]?.focus();
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background to-muted flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="w-full max-w-md"
      >
        <Card className="border-0 shadow-xl">
          <CardHeader className="space-y-1 text-center">
            <div className="mb-4">
              <h1 className="text-4xl font-bold text-primary">ZENO</h1>
              <p className="text-sm text-muted-foreground">Services You Can Count On</p>
            </div>
            
            <div className="flex justify-center mb-4">
              <div className="w-16 h-16 rounded-full bg-blue-100 flex items-center justify-center">
                <Shield className="h-8 w-8 text-blue-600" />
              </div>
            </div>
            
            <CardTitle className="text-2xl">Verify Your Email</CardTitle>
            <CardDescription className="text-base">
              Enter the 6-digit code sent to
            </CardDescription>
            <div className="text-lg font-medium text-primary break-all">
              {email}
            </div>
          </CardHeader>
          
          <CardContent className="space-y-6">
            {/* Verification Status */}
            {verificationStatus === 'success' && (
              <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="bg-green-50 border border-green-200 rounded-lg p-4"
              >
                <div className="flex items-center">
                  <CheckCircle className="h-5 w-5 text-green-600 mr-2" />
                  <span className="font-medium text-green-800">Email verified successfully!</span>
                </div>
                <p className="text-sm text-green-700 mt-1">
                  Redirecting to login page...
                </p>
              </motion.div>
            )}
            
            {verificationStatus === 'error' && (
              <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="bg-red-50 border border-red-200 rounded-lg p-4"
              >
                <div className="flex items-center">
                  <XCircle className="h-5 w-5 text-red-600 mr-2" />
                  <span className="font-medium text-red-800">Verification Failed</span>
                </div>
                <p className="text-sm text-red-700 mt-1">
                  {errorMessage}
                </p>
              </motion.div>
            )}

            {/* Verification Code Inputs */}
            <div className="space-y-4">
              <Label className="text-center block">Verification Code</Label>
              
              <div className="flex justify-center space-x-2">
                {verificationCode.map((digit, index) => (
                  <motion.div
                    key={index}
                    initial={{ scale: 0.8 }}
                    animate={{ scale: 1 }}
                    transition={{ delay: index * 0.05 }}
                  >
                    <Input
                      ref={(el) => inputRefs.current[index] = el}
                      type="text"
                      inputMode="numeric"
                      pattern="[0-9]*"
                      maxLength={1}
                      value={digit}
                      onChange={(e) => handleCodeChange(index, e.target.value)}
                      onKeyDown={(e) => handleKeyDown(index, e)}
                      className="w-12 h-12 text-center text-xl font-bold border-2"
                      disabled={isLoading || verificationStatus === 'success'}
                    />
                  </motion.div>
                ))}
              </div>
              
              <div className="flex justify-between items-center">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={handleClearAll}
                  disabled={isLoading || verificationStatus === 'success'}
                  className="text-xs"
                >
                  Clear All
                </Button>
                
                <div className="text-sm text-muted-foreground">
                  {verificationCode.filter(d => d).length}/6 digits
                </div>
              </div>
            </div>

            {/* Verify Button */}
            <Button
              onClick={handleVerifyEmail}
              className="w-full bg-secondary hover:bg-secondary/90 text-white"
              size="lg"
              disabled={isLoading || verificationCode.join('').length !== 6 || verificationStatus === 'success'}
            >
              {isLoading ? (
                <>
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                  Verifying...
                </>
              ) : (
                <>
                  Verify Email
                  <CheckCircle className="ml-2 h-4 w-4" />
                </>
              )}
            </Button>

            {/* Resend Code Section */}
            <div className="space-y-3">
              <Button
                onClick={handleResendVerification}
                className="w-full"
                variant="outline"
                disabled={isResending || resendCooldown > 0 || verificationStatus === 'success'}
              >
                {isResending ? (
                  <>
                    <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                    Sending...
                  </>
                ) : (
                  <>
                    <Mail className="h-4 w-4 mr-2" />
                    {resendCooldown > 0 
                      ? `Resend in ${resendCooldown}s` 
                      : 'Resend Verification Code'}
                  </>
                )}
              </Button>
              
              <p className="text-xs text-muted-foreground text-center">
                Didn't receive the code? Click above to resend.
              </p>
            </div>

            {/* Verification Tips */}
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <h4 className="font-semibold text-blue-800 mb-2">Verification Tips:</h4>
              <ul className="text-sm text-blue-700 space-y-1">
                <li className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>Check your spam folder if you don't see the email</span>
                </li>
                <li className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>Codes expire after 24 hours for security</span>
                </li>
                <li className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>Enter the code exactly as shown in the email</span>
                </li>
              </ul>
            </div>
          </CardContent>
          
          <CardFooter className="flex flex-col space-y-3">
            <div className="flex gap-2 w-full">
              <Button
                onClick={handleGoBack}
                variant="outline"
                className="flex-1"
                disabled={isLoading || verificationStatus === 'success'}
              >
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back
              </Button>
              
              <Button
                onClick={handleGoToLogin}
                variant="ghost"
                className="flex-1"
                disabled={verificationStatus === 'success'}
              >
                Go to Login
              </Button>
            </div>
            
            <div className="text-center text-sm text-muted-foreground pt-4 border-t">
              <p>
                Having trouble?{" "}
                <Link to="/contact" className="text-secondary hover:underline">
                  Contact Support
                </Link>
              </p>
            </div>
          </CardFooter>
        </Card>
        
        {/* Additional Help Section */}
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="mt-6"
        >
          <Card className="border-0 shadow-md">
            <CardContent className="p-4">
              <h4 className="font-semibold mb-2">Need Help with Verification?</h4>
              <div className="text-sm text-muted-foreground space-y-2">
                <p>
                  If you're experiencing issues with email verification:
                </p>
                <ul className="list-disc pl-4 space-y-1">
                  <li>Ensure you're using the same email you registered with</li>
                  <li>Check that your email service isn't blocking our messages</li>
                  <li>Try using a different browser or device</li>
                </ul>
                <p className="pt-2">
                  Email us at{" "}
                  <a href="mailto:support@zenoservices.co.ke" className="text-secondary hover:underline">
                    support@zenoservices.co.ke
                  </a>{" "}
                  if you need further assistance
                </p>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </motion.div>
    </div>
  );
};

export default VerifyEmail;