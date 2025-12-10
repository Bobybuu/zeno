import { createRoot } from "react-dom/client";
import React from "react";
import App from "./App.tsx";
import { AuthProvider } from "./context/AuthContext"; // ✅ correct import
import "./index.css";

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <AuthProvider>
      <App />
    </AuthProvider>
  </React.StrictMode>
);
