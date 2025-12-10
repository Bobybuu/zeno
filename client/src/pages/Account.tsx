import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { User, Phone, LogOut, Loader2, Mail, MapPin, Shield } from "lucide-react";
import { toast } from "sonner";
import BottomNav from "@/components/BottomNav";
import { useAuth } from "@/context/AuthContext";

interface Profile {
  id: number;
  email: string;
  username: string;
  first_name: string;
  last_name: string;
  phone_number: string;
  user_type: string;
  location: string;
  is_verified: boolean;
  phone_verified: boolean;
  date_joined: string;
}

const Account = () => {
  const navigate = useNavigate();
  const { currentUser, logout, checkAuthentication } = useAuth();
  const [profile, setProfile] = useState<Profile | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      // Check if user is authenticated via the AuthContext
      if (!currentUser) {
        // If no current user, try to check authentication
        await checkAuthentication?.();
        
        // If still no user after checking, redirect to login
        if (!currentUser) {
          navigate("/login");
          return;
        }
      }
      
      // Set profile data from currentUser
      setProfile(currentUser as Profile);
    } catch (error) {
      console.error("Auth check failed:", error);
      navigate("/login");
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await logout();
      toast.success("Logged out successfully");
      navigate("/login");
    } catch (error) {
      console.error("Error logging out:", error);
      toast.error("Failed to logout");
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  };

  const getUserTypeDisplay = (userType: string) => {
    const typeMap: { [key: string]: string } = {
      'customer': 'Customer',
      'vendor': 'Service Vendor',
      'mechanic': 'Mechanic',
      'admin': 'Administrator'
    };
    return typeMap[userType] || userType;
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background pb-20">
      <header className="bg-primary text-primary-foreground py-6 px-4">
        <h1 className="text-2xl font-bold">My Account</h1>
      </header>

      <main className="container max-w-2xl mx-auto px-4 py-6 space-y-4">
        {/* Profile Card */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <User className="h-5 w-5" />
              Profile Information
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">First Name</label>
                <p className="text-lg">
                  {profile?.first_name || "Not set"}
                </p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Last Name</label>
                <p className="text-lg">
                  {profile?.last_name || "Not set"}
                </p>
              </div>
            </div>

            <div>
              <label className="text-sm font-medium text-muted-foreground flex items-center gap-1">
                <Mail className="h-4 w-4" />
                Email Address
              </label>
              <p className="text-lg">{profile?.email}</p>
            </div>

            <div>
              <label className="text-sm font-medium text-muted-foreground flex items-center gap-1">
                <User className="h-4 w-4" />
                Username
              </label>
              <p className="text-lg">{profile?.username}</p>
            </div>

            <div>
              <label className="text-sm font-medium text-muted-foreground flex items-center gap-1">
                <Phone className="h-4 w-4" />
                Phone Number
              </label>
              <div className="flex items-center justify-between">
                <p className="text-lg">{profile?.phone_number || "Not available"}</p>
                {profile?.phone_verified && (
                  <span className="flex items-center gap-1 text-xs bg-green-100 text-green-800 px-2 py-1 rounded-full">
                    <Shield className="h-3 w-3" />
                    Verified
                  </span>
                )}
              </div>
            </div>

            <div>
              <label className="text-sm font-medium text-muted-foreground flex items-center gap-1">
                <MapPin className="h-4 w-4" />
                Location
              </label>
              <p className="text-lg">{profile?.location || "Not set"}</p>
            </div>

            <div>
              <label className="text-sm font-medium text-muted-foreground">Account Type</label>
              <p className="text-lg font-medium text-secondary">
                {getUserTypeDisplay(profile?.user_type || 'customer')}
              </p>
            </div>

            <div>
              <label className="text-sm font-medium text-muted-foreground">Member Since</label>
              <p className="text-lg">
                {profile?.date_joined ? formatDate(profile.date_joined) : "N/A"}
              </p>
            </div>

            <div>
              <label className="text-sm font-medium text-muted-foreground">Account Status</label>
              <div className="flex gap-2 mt-1">
                {profile?.is_verified && (
                  <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                    Verified
                  </span>
                )}
                {profile?.phone_verified && (
                  <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                    Phone Verified
                  </span>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Account Actions Card */}
        <Card>
          <CardHeader>
            <CardTitle>Account Actions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Button
              variant="outline"
              className="w-full justify-start"
              onClick={() => navigate("/edit-profile")}
            >
              Edit Profile
            </Button>
            
            <Button
              variant="outline"
              className="w-full justify-start"
              onClick={() => navigate("/change-password")}
            >
              Change Password
            </Button>

            {profile?.user_type === 'vendor' && (
              <Button
                variant="outline"
                className="w-full justify-start"
                onClick={() => navigate("/vendor/dashboard")}
              >
                Vendor Dashboard
              </Button>
            )}

            {profile?.user_type === 'mechanic' && (
              <Button
                variant="outline"
                className="w-full justify-start"
                onClick={() => navigate("/mechanic/dashboard")}
              >
                Mechanic Dashboard
              </Button>
            )}
          </CardContent>
        </Card>

        {/* Logout Button */}
        <Button
          onClick={handleLogout}
          variant="destructive"
          className="w-full"
          size="lg"
        >
          <LogOut className="h-5 w-5 mr-2" />
          Logout
        </Button>

        {/* Debug Info (remove in production) */}
        {process.env.NODE_ENV === 'development' && (
          <Card className="bg-muted/50">
            <CardHeader>
              <CardTitle className="text-sm">Debug Info</CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="text-xs overflow-auto">
                {JSON.stringify(profile, null, 2)}
              </pre>
            </CardContent>
          </Card>
        )}
      </main>

      <BottomNav />
    </div>
  );
};

export default Account;