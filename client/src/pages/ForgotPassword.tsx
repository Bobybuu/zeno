// src/pages/ForgotPassword.tsx
import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Phone, ArrowLeft, ChevronRight, Lock, Key } from "lucide-react";
import { motion } from "framer-motion";
import { toast } from "sonner";
import { authAPI } from "@/services/api";

const ForgotPassword = () => {
  const navigate = useNavigate();
  const [step, setStep] = useState<"phone" | "code" | "reset">("phone");
  const [loading, setLoading] = useState(false);
  const [phoneNumber, setPhoneNumber] = useState("");
  const [resetCode, setResetCode] = useState("");
  const [resetToken, setResetToken] = useState("");
  const [passwords, setPasswords] = useState({
    new_password: "",
    confirm_password: "",
  });

  const handleSendResetCode = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!phoneNumber) {
      toast.error("Please enter your phone number");
      return;
    }

    // Validate phone number format
    const phoneRegex = /^\+?[\d\s-()]{10,}$/;
    if (!phoneRegex.test(phoneNumber)) {
      toast.error("Please enter a valid phone number with country code");
      return;
    }

    setLoading(true);

    try {
      const response = await authAPI.forgotPassword(phoneNumber);
      toast.success(response.data.message || "Reset code sent to your phone");
      setStep("code");
    } catch (error: any) {
      toast.error(error.response?.data?.error || "Failed to send reset code");
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyResetCode = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!resetCode || resetCode.length !== 6) {
      toast.error("Please enter a valid 6-digit reset code");
      return;
    }

    setLoading(true);

    try {
      const response = await authAPI.verifyResetCode({
        phone_number: phoneNumber,
        reset_code: resetCode,
      });
      
      setResetToken(response.data.reset_token);
      toast.success("Reset code verified successfully");
      setStep("reset");
    } catch (error: any) {
      toast.error(error.response?.data?.error || "Invalid reset code");
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();

    if (passwords.new_password !== passwords.confirm_password) {
      toast.error("Passwords don't match");
      return;
    }

    if (passwords.new_password.length < 6) {
      toast.error("Password must be at least 6 characters long");
      return;
    }

    setLoading(true);

    try {
      await authAPI.resetPassword({
        reset_token: resetToken,
        new_password: passwords.new_password,
        confirm_password: passwords.confirm_password,
      });
      
      toast.success("Password reset successfully!");
      navigate("/login");
    } catch (error: any) {
      toast.error(error.response?.data?.error || "Failed to reset password");
    } finally {
      setLoading(false);
    }
  };

  const handleResendCode = async () => {
    setLoading(true);
    
    try {
      const response = await authAPI.forgotPassword(phoneNumber);
      toast.success("Reset code sent again");
    } catch (error: any) {
      toast.error(error.response?.data?.error || "Failed to resend code");
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    if (name === "phoneNumber") {
      setPhoneNumber(value);
    } else if (name === "new_password") {
      setPasswords({ ...passwords, new_password: value });
    } else if (name === "confirm_password") {
      setPasswords({ ...passwords, confirm_password: value });
    }
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
              <h1 className="text-4xl font-bold text-primary">zeNO</h1>
              <p className="text-sm text-muted-foreground">Trusted Reliable Services</p>
            </div>
            
            {step === "phone" && (
              <>
                <CardTitle className="text-2xl">Reset Password</CardTitle>
                <CardDescription>
                  Enter your phone number to receive a reset code
                </CardDescription>
              </>
            )}
            
            {step === "code" && (
              <>
                <CardTitle className="text-2xl">Enter Reset Code</CardTitle>
                <CardDescription>
                  Enter the 6-digit code sent to {phoneNumber}
                </CardDescription>
              </>
            )}
            
            {step === "reset" && (
              <>
                <CardTitle className="text-2xl">New Password</CardTitle>
                <CardDescription>
                  Create your new password
                </CardDescription>
              </>
            )}
          </CardHeader>

          <CardContent>
            {/* Step 1: Phone Input */}
            {step === "phone" && (
              <form onSubmit={handleSendResetCode} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="phoneNumber">Phone Number</Label>
                  <div className="relative">
                    <Phone className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                      id="phoneNumber"
                      name="phoneNumber"
                      type="tel"
                      placeholder="+254712345678"
                      value={phoneNumber}
                      onChange={handleChange}
                      className="pl-10"
                      required
                    />
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Enter your registered phone number with country code
                  </p>
                </div>

                <Button 
                  type="submit" 
                  className="w-full bg-secondary hover:bg-secondary/90 text-white font-semibold"
                  size="lg"
                  disabled={loading}
                >
                  {loading ? "Sending Code..." : "Send Reset Code"}
                  <ChevronRight className="ml-2 h-4 w-4" />
                </Button>
              </form>
            )}

            {/* Step 2: Reset Code Verification */}
            {step === "code" && (
              <form onSubmit={handleVerifyResetCode} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="resetCode">Reset Code</Label>
                  <div className="relative">
                    <Key className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                      id="resetCode"
                      type="text"
                      placeholder="123456"
                      value={resetCode}
                      onChange={(e) => setResetCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      className="pl-10 text-center text-lg font-mono"
                      maxLength={6}
                      required
                    />
                  </div>
                  <p className="text-xs text-muted-foreground text-center">
                    Enter the 6-digit code sent to your phone
                  </p>
                </div>

                <Button 
                  type="submit" 
                  className="w-full bg-secondary hover:bg-secondary/90 text-white font-semibold"
                  size="lg"
                  disabled={loading || resetCode.length !== 6}
                >
                  {loading ? "Verifying..." : "Verify Code"}
                  <ChevronRight className="ml-2 h-4 w-4" />
                </Button>

                <div className="text-center">
                  <Button
                    type="button"
                    variant="link"
                    onClick={handleResendCode}
                    disabled={loading}
                    className="text-secondary"
                  >
                    Resend Code
                  </Button>
                </div>
              </form>
            )}

            {/* Step 3: New Password */}
            {step === "reset" && (
              <form onSubmit={handleResetPassword} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="new_password">New Password</Label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                      id="new_password"
                      name="new_password"
                      type="password"
                      placeholder="Enter new password"
                      value={passwords.new_password}
                      onChange={handleChange}
                      className="pl-10"
                      required
                      minLength={6}
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="confirm_password">Confirm Password</Label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                      id="confirm_password"
                      name="confirm_password"
                      type="password"
                      placeholder="Confirm new password"
                      value={passwords.confirm_password}
                      onChange={handleChange}
                      className="pl-10"
                      required
                      minLength={6}
                    />
                  </div>
                </div>

                <Button 
                  type="submit" 
                  className="w-full bg-secondary hover:bg-secondary/90 text-white font-semibold"
                  size="lg"
                  disabled={loading}
                >
                  {loading ? "Resetting Password..." : "Reset Password"}
                  <ChevronRight className="ml-2 h-4 w-4" />
                </Button>
              </form>
            )}

            {/* Back Button */}
            {step !== "phone" && (
              <div className="text-center mt-4">
                <Button
                  type="button"
                  variant="link"
                  onClick={() => setStep(step === "reset" ? "code" : "phone")}
                  className="text-muted-foreground"
                >
                  <ArrowLeft className="h-4 w-4 mr-1" />
                  Go Back
                </Button>
              </div>
            )}

            {/* Footer Links */}
            <div className="text-center text-sm mt-6 pt-4 border-t">
              <span className="text-muted-foreground">Remember your password? </span>
              <Link to="/login" className="text-secondary hover:underline font-semibold">
                Back to Login
              </Link>
            </div>
          </CardContent>

          {/* Development Note */}
          {process.env.NODE_ENV === 'development' && step === "code" && (
            <div className="px-6 pb-4">
              <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3">
                <p className="text-sm text-yellow-800 text-center">
                  <strong>Development Note:</strong> Check your Django console for the reset code
                </p>
              </div>
            </div>
          )}

          {/* Phone Authentication Info */}
          <div className="px-6 pb-4">
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
              <p className="text-sm text-blue-800 text-center">
                <strong>Phone Authentication:</strong> Reset codes are sent via SMS to your registered phone number
              </p>
            </div>
          </div>
        </Card>
      </motion.div>
    </div>
  );
};

export default ForgotPassword;