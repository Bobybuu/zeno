// src/pages/CheckEmail.tsx
import { useEffect, useState } from "react";
import { useLocation, useNavigate, Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Mail, CheckCircle, RefreshCw, ArrowRight, Home } from "lucide-react";
import { motion } from "framer-motion";
import { toast } from "sonner";
import { useAuth } from "@/context/AuthContext";

const CheckEmail = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { resendVerificationEmail } = useAuth();
  
  const [email, setEmail] = useState<string>("");
  const [isLoading, setIsLoading] = useState(false);
  const [resendCooldown, setResendCooldown] = useState(0);
  const [emailSent, setEmailSent] = useState(false);

  useEffect(() => {
    // Get email from location state or localStorage
    const stateEmail = location.state?.email;
    const storedEmail = localStorage.getItem('pending_user_email');
    
    if (stateEmail) {
      setEmail(stateEmail);
      localStorage.setItem('pending_user_email', stateEmail);
    } else if (storedEmail) {
      setEmail(storedEmail);
    } else {
      // No email found, redirect to register
      navigate("/register");
    }
  }, [location, navigate]);

  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (resendCooldown > 0) {
      timer = setTimeout(() => setResendCooldown(resendCooldown - 1), 1000);
    }
    return () => clearTimeout(timer);
  }, [resendCooldown]);

  const handleResendVerification = async () => {
    if (!email || resendCooldown > 0) return;
    
    setIsLoading(true);
    try {
      const result = await resendVerificationEmail(email);
      
      if (result.success) {
        toast.success("Verification email sent successfully!");
        setEmailSent(true);
        setResendCooldown(60); // 60 seconds cooldown
      } else {
        toast.error(result.error?.message || "Failed to resend verification email");
      }
    } catch (error) {
      toast.error("An unexpected error occurred");
    } finally {
      setIsLoading(false);
    }
  };

  const handleGoToVerify = () => {
    navigate("/verify-email", { state: { email } });
  };

  const handleGoToLogin = () => {
    localStorage.removeItem('pending_user_email');
    navigate("/login");
  };

  const handleGoHome = () => {
    navigate("/");
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
              <div className="w-16 h-16 rounded-full bg-green-100 flex items-center justify-center">
                <Mail className="h-8 w-8 text-green-600" />
              </div>
            </div>
            
            <CardTitle className="text-2xl">Check Your Email</CardTitle>
            <CardDescription className="text-lg">
              We've sent a verification email to
            </CardDescription>
            <div className="text-lg font-medium text-primary break-all">
              {email}
            </div>
          </CardHeader>
          
          <CardContent className="space-y-6">
            {/* Instructions */}
            <div className="space-y-3">
              <h3 className="font-semibold text-lg">Next Steps:</h3>
              <div className="space-y-2">
                <div className="flex items-start">
                  <CheckCircle className="h-5 w-5 text-green-500 mr-2 mt-0.5 flex-shrink-0" />
                  <span>Open the email from Zeno Services</span>
                </div>
                <div className="flex items-start">
                  <CheckCircle className="h-5 w-5 text-green-500 mr-2 mt-0.5 flex-shrink-0" />
                  <span>Click the verification link in the email</span>
                </div>
                <div className="flex items-start">
                  <CheckCircle className="h-5 w-5 text-green-500 mr-2 mt-0.5 flex-shrink-0" />
                  <span>Return here to complete your registration</span>
                </div>
              </div>
            </div>

            {/* Email Tips */}
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <h4 className="font-semibold text-blue-800 mb-2">Can't find the email?</h4>
              <ul className="text-sm text-blue-700 space-y-1">
                <li className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>Check your spam or junk folder</span>
                </li>
                <li className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>Make sure you entered the correct email address</span>
                </li>
                <li className="flex items-start">
                  <span className="mr-2">•</span>
                  <span>Wait a few minutes - emails may be delayed</span>
                </li>
              </ul>
            </div>

            {/* Resend Email Button */}
            <div className="space-y-3">
              <Button
                onClick={handleResendVerification}
                className="w-full"
                variant="outline"
                disabled={isLoading || resendCooldown > 0}
              >
                {isLoading ? (
                  <>
                    <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                    Sending...
                  </>
                ) : (
                  <>
                    <Mail className="h-4 w-4 mr-2" />
                    {resendCooldown > 0 
                      ? `Resend in ${resendCooldown}s` 
                      : emailSent 
                        ? 'Email Sent Again!' 
                        : 'Resend Verification Email'}
                  </>
                )}
              </Button>
              
              <p className="text-xs text-muted-foreground text-center">
                Didn't receive the email? Click above to resend.
              </p>
            </div>
          </CardContent>
          
          <CardFooter className="flex flex-col space-y-3">
            <Button 
              onClick={handleGoToVerify}
              className="w-full bg-secondary hover:bg-secondary/90 text-white"
              size="lg"
            >
              I've Verified My Email
              <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
            
            <div className="flex gap-2 w-full">
              <Button
                onClick={handleGoToLogin}
                variant="outline"
                className="flex-1"
              >
                Go to Login
              </Button>
              
              <Button
                onClick={handleGoHome}
                variant="ghost"
                className="flex-1"
              >
                <Home className="h-4 w-4 mr-2" />
                Home
              </Button>
            </div>
            
            <div className="text-center text-sm text-muted-foreground pt-4 border-t">
              <p>Need help? <Link to="/contact" className="text-secondary hover:underline">Contact Support</Link></p>
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
              <h4 className="font-semibold mb-2">Verification Issues?</h4>
              <div className="text-sm text-muted-foreground space-y-2">
                <p>
                  If you're still having trouble receiving the verification email after 10 minutes, 
                  please ensure:
                </p>
                <ul className="list-disc pl-4 space-y-1">
                  <li>Your email service isn't blocking our messages</li>
                  <li>You've checked all folders including spam and promotions</li>
                  <li>The email address "{email}" is correct</li>
                </ul>
                <p className="pt-2">
                  Still need help? Email us at{" "}
                  <a href="mailto:support@zenoservices.co.ke" className="text-secondary hover:underline">
                    support@zenoservices.co.ke
                  </a>
                </p>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </motion.div>
    </div>
  );
};

export default CheckEmail;