import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.tsx";
import { ThemeProvider } from "./context/ThemeContext.tsx";
import { GuardianProvider } from "./context/GuardianContext.tsx";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <GuardianProvider>
        <App />
      </GuardianProvider>
    </ThemeProvider>
  </StrictMode>,
);
