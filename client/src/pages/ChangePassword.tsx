// src/pages/ChangePassword.tsx
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Lock, ArrowLeft, Key, Eye, EyeOff } from "lucide-react";
import { toast } from "sonner";
import BottomNav from "@/components/BottomNav";
import { authAPI } from "@/services/api";

const ChangePassword = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [showPasswords, setShowPasswords] = useState({
    current: false,
    new: false,
    confirm: false,
  });
  const [formData, setFormData] = useState({
    old_password: "",
    new_password1: "",
    new_password2: "",
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // Validation
    if (!formData.old_password || !formData.new_password1 || !formData.new_password2) {
      toast.error("Please fill in all fields");
      return;
    }

    if (formData.new_password1 !== formData.new_password2) {
      toast.error("New passwords don't match");
      return;
    }

    if (formData.new_password1.length < 6) {
      toast.error("New password must be at least 6 characters long");
      return;
    }

    if (formData.old_password === formData.new_password1) {
      toast.error("New password must be different from current password");
      return;
    }

    setLoading(true);

    try {
      // Call backend API to change password
      const response = await authAPI.changePassword({
        old_password: formData.old_password,
        new_password1: formData.new_password1,
        new_password2: formData.new_password2,
      });
      
      toast.success("Password changed successfully");
      
      // Clear form
      setFormData({
        old_password: "",
        new_password1: "",
        new_password2: "",
      });
      
      // Navigate back to account page after a short delay
      setTimeout(() => {
        navigate("/account");
      }, 1500);
      
    } catch (error: any) {
      console.error("Password change error:", error);
      
      // Handle specific error cases
      if (error.response?.data?.errors?.old_password) {
        toast.error(error.response.data.errors.old_password[0]);
      } else if (error.response?.data?.errors?.new_password2) {
        toast.error(error.response.data.errors.new_password2[0]);
      } else if (error.response?.data?.error) {
        toast.error(error.response.data.error);
      } else {
        toast.error("Failed to change password. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const togglePasswordVisibility = (field: keyof typeof showPasswords) => {
    setShowPasswords({
      ...showPasswords,
      [field]: !showPasswords[field],
    });
  };

  const passwordStrength = formData.new_password1 ? (
    formData.new_password1.length < 6 ? "weak" :
    formData.new_password1.length < 8 ? "fair" :
    /[0-9]/.test(formData.new_password1) && /[!@#$%^&*]/.test(formData.new_password1) ? "strong" : "good"
  ) : null;

  const getPasswordStrengthColor = (strength: string | null) => {
    switch (strength) {
      case "weak": return "bg-red-500";
      case "fair": return "bg-yellow-500";
      case "good": return "bg-blue-500";
      case "strong": return "bg-green-500";
      default: return "bg-gray-200";
    }
  };

  const getPasswordStrengthText = (strength: string | null) => {
    switch (strength) {
      case "weak": return "Weak";
      case "fair": return "Fair";
      case "good": return "Good";
      case "strong": return "Strong";
      default: return "";
    }
  };

  return (
    <div className="min-h-screen bg-background pb-20">
      {/* Header */}
      <header className="bg-primary text-primary-foreground py-4 px-4 sticky top-0 z-10">
        <div className="container max-w-2xl mx-auto flex items-center gap-4">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => navigate("/account")}
            className="text-primary-foreground hover:bg-primary-foreground/20"
          >
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <h1 className="text-xl font-bold">Change Password</h1>
        </div>
      </header>

      <main className="container max-w-2xl mx-auto px-4 py-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5" />
              Change Password
            </CardTitle>
            <CardDescription>
              Update your password to keep your account secure
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="old_password">Current Password</Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="old_password"
                    name="old_password"
                    type={showPasswords.current ? "text" : "password"}
                    placeholder="Enter current password"
                    value={formData.old_password}
                    onChange={handleChange}
                    className="pl-10 pr-10"
                    required
                    disabled={loading}
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                    onClick={() => togglePasswordVisibility('current')}
                    disabled={loading}
                  >
                    {showPasswords.current ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="new_password1">New Password</Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="new_password1"
                    name="new_password1"
                    type={showPasswords.new ? "text" : "password"}
                    placeholder="Enter new password"
                    value={formData.new_password1}
                    onChange={handleChange}
                    className="pl-10 pr-10"
                    required
                    minLength={6}
                    disabled={loading}
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                    onClick={() => togglePasswordVisibility('new')}
                    disabled={loading}
                  >
                    {showPasswords.new ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </Button>
                </div>
                
                {/* Password Strength Indicator */}
                {formData.new_password1 && (
                  <div className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-muted-foreground">Password strength:</span>
                      <span className={`font-medium ${
                        passwordStrength === 'weak' ? 'text-red-600' :
                        passwordStrength === 'fair' ? 'text-yellow-600' :
                        passwordStrength === 'good' ? 'text-blue-600' :
                        'text-green-600'
                      }`}>
                        {getPasswordStrengthText(passwordStrength)}
                      </span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div 
                        className={`h-2 rounded-full transition-all duration-300 ${
                          getPasswordStrengthColor(passwordStrength)
                        }`}
                        style={{
                          width: passwordStrength === 'weak' ? '25%' :
                                 passwordStrength === 'fair' ? '50%' :
                                 passwordStrength === 'good' ? '75%' :
                                 passwordStrength === 'strong' ? '100%' : '0%'
                        }}
                      />
                    </div>
                  </div>
                )}
                
                <p className="text-xs text-muted-foreground">
                  Password must be at least 6 characters long
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="new_password2">Confirm New Password</Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="new_password2"
                    name="new_password2"
                    type={showPasswords.confirm ? "text" : "password"}
                    placeholder="Confirm new password"
                    value={formData.new_password2}
                    onChange={handleChange}
                    className="pl-10 pr-10"
                    required
                    minLength={6}
                    disabled={loading}
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                    onClick={() => togglePasswordVisibility('confirm')}
                    disabled={loading}
                  >
                    {showPasswords.confirm ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </Button>
                </div>
                {formData.new_password2 && formData.new_password1 !== formData.new_password2 && (
                  <p className="text-xs text-red-600">Passwords do not match</p>
                )}
              </div>

              <div className="flex gap-3 pt-4">
                <Button
                  type="button"
                  variant="outline"
                  className="flex-1"
                  onClick={() => navigate("/account")}
                  disabled={loading}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  className="flex-1 bg-secondary hover:bg-secondary/90"
                  disabled={loading || 
                    !formData.old_password || 
                    !formData.new_password1 || 
                    !formData.new_password2 ||
                    formData.new_password1 !== formData.new_password2 ||
                    formData.new_password1.length < 6
                  }
                >
                  {loading ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Updating...
                    </>
                  ) : (
                    <>
                      <Key className="h-4 w-4 mr-2" />
                      Update Password
                    </>
                  )}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>

        {/* Security Tips */}
        <Card className="mt-6 bg-muted/50">
          <CardHeader>
            <CardTitle className="text-sm">Password Tips</CardTitle>
          </CardHeader>
          <CardContent className="text-sm space-y-2">
            <p>• Use at least 8 characters for better security</p>
            <p>• Include numbers, uppercase, and special characters</p>
            <p>• Avoid using personal information like phone numbers</p>
            <p>• Don't reuse passwords from other sites</p>
            <p>• Consider using a password manager</p>
          </CardContent>
        </Card>
      </main>

      <BottomNav />
    </div>
  );
};

export default ChangePassword;