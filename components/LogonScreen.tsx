import { PRODUCT_NAME } from "@/lib/brand";
import { Clock } from "./Clock";

export function LogonScreen({ children }: { children: React.ReactNode }) {
  return (
    <div className="screen">
      <p className="wordmark">{PRODUCT_NAME}</p>
      <main className="panel">{children}</main>
      <Clock />
    </div>
  );
}
