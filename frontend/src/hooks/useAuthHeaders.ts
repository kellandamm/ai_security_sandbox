import { useCallback } from "react";
import { useMsal } from "@azure/msal-react";
import { loginRequest, authEnabled } from "../authConfig";

/**
 * Returns a function that produces auth headers for API calls.
 * Acquires a token silently and falls back to popup when needed.
 *
 * When auth is not configured (local dev without AAD), returns
 * empty headers so the app degrades gracefully.
 */
export function useAuthHeaders(): () => Promise<Record<string, string>> {
  const { instance, accounts } = useMsal();

  return useCallback(async () => {
    const headers: Record<string, string> = {};

    if (!authEnabled) {
      return headers;
    }

    let account = instance.getActiveAccount() ?? accounts[0] ?? null;

    if (!account) {
      const loginResponse = await instance.loginPopup(loginRequest);
      account = loginResponse.account ?? instance.getActiveAccount() ?? null;

      if (!account) {
        throw new Error("Microsoft sign-in is required before starting a run.");
      }

      instance.setActiveAccount(account);
    }

    try {
      const response = await instance.acquireTokenSilent({
        ...loginRequest,
        account,
      });
      headers["Authorization"] = `Bearer ${response.accessToken}`;
      return headers;
    } catch {
      // Silent acquisition failed — try popup
      const response = await instance.acquireTokenPopup({
        ...loginRequest,
        account,
      });

      if (response.account) {
        instance.setActiveAccount(response.account);
      }

      headers["Authorization"] = `Bearer ${response.accessToken}`;
    }

    return headers;
  }, [instance, accounts]);
}
