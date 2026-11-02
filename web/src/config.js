// Public service URL only. No deployment credentials or administrator secrets.
export const API_BASE = ["localhost", "127.0.0.1"].includes(location.hostname)
  ? ""
  : "https://secretvault-api-thienphuc.onrender.com";
