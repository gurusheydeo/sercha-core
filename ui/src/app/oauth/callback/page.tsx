"use client";

import { useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Loader2 } from "lucide-react";
import Image from "next/image";

/**
 * OAuth Callback Page
 *
 * This page is no longer used for client-side OAuth exchange.
 * OAuth callback is now handled server-side at /api/v1/oauth/callback,
 * which redirects to /oauth/complete with the connection details.
 *
 * This page exists only for backwards compatibility and will redirect
 * users to the appropriate location.
 */

function OAuthCallbackContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    // Check if we have error params (provider denied authorization)
    const errorParam = searchParams.get("error");
    const errorDescription = searchParams.get("error_description");

    if (errorParam) {
      // Redirect to complete page with error params preserved
      const params = new URLSearchParams();
      params.set("error", errorParam);
      if (errorDescription) params.set("error_description", errorDescription);
      router.replace(`/oauth/complete?${params.toString()}`);
      return;
    }

    // Check if we have code/state params (old client-side flow)
    const code = searchParams.get("code");
    const state = searchParams.get("state");

    if (code && state) {
      // This shouldn't happen anymore - OAuth callback goes to backend
      // Redirect to sources with an error message
      router.replace("/admin/sources?error=oauth_flow_changed");
      return;
    }

    // No params - just redirect to sources
    router.replace("/admin/sources");
  }, [searchParams, router]);

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-gradient-to-b from-sercha-snow to-sercha-mist px-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="mb-8 flex justify-center">
          <Image
            src="/logo-wordmark.png"
            alt="Sercha"
            width={180}
            height={48}
            className="h-12 w-auto"
            priority
          />
        </div>

        {/* Loading Card */}
        <div className="rounded-2xl border border-sercha-silverline bg-white p-8 shadow-sm">
          <div className="flex flex-col items-center text-center">
            <Loader2 className="mb-4 h-12 w-12 animate-spin text-sercha-indigo" />
            <h1 className="text-xl font-semibold text-sercha-ink-slate">
              Redirecting...
            </h1>
            <p className="mt-2 text-sm text-sercha-fog-grey">
              Please wait while we redirect you.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function OAuthCallbackPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen flex-col items-center justify-center bg-gradient-to-b from-sercha-snow to-sercha-mist px-4">
          <div className="w-full max-w-md">
            <div className="mb-8 flex justify-center">
              <Image
                src="/logo-wordmark.png"
                alt="Sercha"
                width={180}
                height={48}
                className="h-12 w-auto"
                priority
              />
            </div>
            <div className="rounded-2xl border border-sercha-silverline bg-white p-8 shadow-sm">
              <div className="flex flex-col items-center text-center">
                <Loader2 className="mb-4 h-12 w-12 animate-spin text-sercha-indigo" />
                <h1 className="text-xl font-semibold text-sercha-ink-slate">
                  Loading...
                </h1>
              </div>
            </div>
          </div>
        </div>
      }
    >
      <OAuthCallbackContent />
    </Suspense>
  );
}
