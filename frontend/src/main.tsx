import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { PublicClientApplication, EventType } from "@azure/msal-browser";
import { MsalProvider } from "@azure/msal-react";
import { msalConfig, authEnabled } from "./authConfig";
import "./index.css";
import App from "./App";
import AppErrorBoundary from "./components/AppErrorBoundary";

const msalInstance = new PublicClientApplication(msalConfig);

// Set the first account as active if one exists (e.g. after page refresh)
const accounts = msalInstance.getAllAccounts();
if (accounts.length > 0) {
  msalInstance.setActiveAccount(accounts[0]);
}
msalInstance.addEventCallback((event) => {
  if (event.eventType === EventType.LOGIN_SUCCESS && event.payload) {
    const payload = event.payload as { account?: unknown };
    if (payload.account) {
      msalInstance.setActiveAccount(payload.account as Parameters<typeof msalInstance.setActiveAccount>[0]);
    }
  }
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <AppErrorBoundary>
      {authEnabled ? (
        <MsalProvider instance={msalInstance}>
          <App />
        </MsalProvider>
      ) : (
        <App />
      )}
    </AppErrorBoundary>
  </StrictMode>
);
