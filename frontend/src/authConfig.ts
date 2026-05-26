import { Configuration, LogLevel } from "@azure/msal-browser";

const clientId = import.meta.env.VITE_AAD_CLIENT_ID ?? "";
const tenantId = import.meta.env.VITE_AAD_TENANT_ID ?? "";

export const msalConfig: Configuration = {
  auth: {
    clientId,
    authority: `https://login.microsoftonline.com/${tenantId}`,
    redirectUri: window.location.origin,
  },
  cache: {
    cacheLocation: "sessionStorage",
    storeAuthStateInCookie: false,
  },
  system: {
    loggerOptions: {
      logLevel: LogLevel.Warning,
    },
  },
};

export const apiScope = clientId ? `api://${clientId}/access_as_user` : "";

export const loginRequest = {
  scopes: apiScope ? [apiScope] : [],
};

/** True when MSAL is configured (VITE_AAD_CLIENT_ID is set). */
export const authEnabled = !!clientId;
