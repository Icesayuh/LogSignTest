import { browserAccountStore, type AccountStore } from "./accounts";
import { isPingOneConfigured, pingOneAccountStore } from "./pingone";

// PingOne when PINGONE_ENV_ID is set; otherwise the built-in cookie demo store,
// so `npm run dev` still works with no PingOne setup.
export const accountStore: AccountStore = isPingOneConfigured() ? pingOneAccountStore : browserAccountStore;
