import type { Metadata, Viewport } from "next";
import { Schibsted_Grotesk } from "next/font/google";
import { BRAND_FIELD_COLOR, PRODUCT_NAME } from "@/lib/brand";
import "./globals.css";

const grotesk = Schibsted_Grotesk({
  subsets: ["latin"],
  weight: ["400", "500", "700", "800"],
  variable: "--font-grotesk",
  display: "swap",
});

export const metadata: Metadata = {
  title: { default: PRODUCT_NAME, template: `%s · ${PRODUCT_NAME}` },
  description: `Sign in or create your ${PRODUCT_NAME} account.`,
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: BRAND_FIELD_COLOR,
  colorScheme: "dark",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={grotesk.variable}>
      <body>{children}</body>
    </html>
  );
}
