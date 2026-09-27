# Free deployment: Render + Supabase

This setup serves the frontend and API together, uses PostgreSQL for reports, and
stores original captures in a private Supabase Storage bucket. Google sign-in
separates each user's captures and reports. Existing shared/local analyses are
not assigned to anyone and are hidden from signed-in accounts. Render can
interrupt in-progress analysis on restart; reupload then.

## 1. Supabase

1. Create a Free project at https://supabase.com/dashboard and save its database
   password. Use a region close to your Render service.
2. Under Storage, create a bucket named `captures`. Leave **Public bucket off**.
   Set the file-size limit to 50 MB; leave MIME restrictions unset.
3. Copy the project URL from the Connect dialog or project API settings.
4. In project Settings > API Keys, copy the legacy `service_role` key (the JWT
   key, not `anon` or the publishable key). This is a server secret.
5. Click Connect > Session pooler. Copy the connection string on port 5432.
   Replace the password placeholder with your database password, URL-encoding
   special characters in the password. Change the prefix to
   `postgresql+psycopg://` and add `?sslmode=require`.
6. Copy the legacy `anon` key as well, for `SUPABASE_ANON_KEY` (this is different
   from the service_role key).
7. Disable the project's Data API in its Data API settings if you do not need it
   elsewhere. This app connects directly to PostgreSQL and uses Storage's API;
   it does not need database tables exposed through the Data API.

Example DATABASE_URL shape (copy your actual host; do not guess it):

```text
postgresql+psycopg://postgres.PROJECT_REF:ENCODED_PASSWORD@POOLER_HOST:5432/postgres?sslmode=require
```

No public bucket policies are needed: the backend uses the service role key.

## 2. Push the deployment code

From the repository root, review and commit the deployment changes, then push:

```powershell
git add Dockerfile.render DEPLOYMENT.md backend/app/main.py backend/app/models/db_models.py backend/app/core/capture_storage.py backend/app/api/routes_upload.py backend/app/api/routes_analysis.py backend/app/api/routes_report.py backend/app/api/routes_auth.py backend/tests/test_hosted_deployment.py backend/tests/test_auth.py src/AuthGate.jsx src/auth.css src/main.jsx src/Startup.jsx src/App.jsx src/api/client.ts
git commit -m "Support Render and Supabase deployment"
git push origin main
```

Never commit database passwords or service keys.

## 3. Render

1. At https://dashboard.render.com choose New > Web Service.
2. Connect GitHub and select `SIH-2026-7/SecureMailScope`.
3. Set:

| Setting | Value |
| --- | --- |
| Branch | `main` |
| Language/runtime | Docker |
| Root directory | Leave blank |
| Dockerfile path | `./Dockerfile.render` |
| Docker build context | Repository root (`.`), if shown |
| Instance type | Free |
| Health check path | `/api/health` |

Leave Docker command unset; the Dockerfile starts the app on Render's PORT.
Do not select the existing root Dockerfile, which builds only the frontend.

Add these environment variables in Render, with no surrounding quotes:

| Variable | Value |
| --- | --- |
| `DATABASE_URL` | Session pooler connection string from step 1 |
| `SUPABASE_URL` | `https://YOUR_PROJECT_REF.supabase.co` |
| `SUPABASE_SERVICE_ROLE_KEY` | Legacy service_role JWT |
| `SUPABASE_STORAGE_BUCKET` | `captures` |
| `SUPABASE_ANON_KEY` | Legacy anon JWT from API Keys |
| `AUTH_REQUIRED` | `true` (also the Docker image default) |
| `APP_URL` | Your exact HTTPS Render URL, with no trailing slash |
| `OMP_NUM_THREADS` | `1` |
| `OPENBLAS_NUM_THREADS` | `1` |

Click Deploy Web Service. If Render has not assigned your URL yet, set APP_URL
once it appears in the service dashboard and redeploy. The app deliberately
refuses to start without its required auth settings. The first build installs
Node/Python dependencies and TShark. Tables are created automatically at startup;
PostgreSQL RLS is enabled without public policies, blocking direct anon/authenticated
Data API access. The backend uses the privileged database connection and checks
ownership itself. Do not add a paid disk or Render PostgreSQL instance. Remove
DEMO_PASSWORD and DEMO_USERNAME; they are unnecessary with Google login.

## 4. Enable Google sign-in

1. Open https://console.cloud.google.com/ and create/select a project.
2. Open Google Auth Platform. Configure Branding (app name and support email)
   and Audience (External for users outside your organization). If the app is
   in Testing, add each tester's Google email under Test users.
3. In Clients, create an OAuth client with application type Web application.
4. Add `https://YOUR_PROJECT_REF.supabase.co/auth/v1/callback` as an Authorized
   redirect URI. Copy the exact callback from Supabase's Google provider page.
5. Copy the Google client ID and client secret into Supabase Authentication >
   Sign In / Providers > Google, enable Google, and save. Keep Google secrets
   in Supabase; do not put them into frontend source or Git.
6. In Supabase Authentication > URL Configuration set Site URL to your Render
   URL, and add `https://YOUR-SERVICE.onrender.com/api/auth/callback` to the
   allowed Redirect URLs. This is a different callback from Google's URI.
7. Open your Render site and choose Continue with Google. For general public
   access, move the Google OAuth app out of Testing when its configuration
   satisfies Google's publishing requirements; otherwise only test users work.

Only Google identity is requested; Gmail access is not used. App sessions last
eight hours or until sign-out. Closing a tab does not delete saved history.
Cookies are Secure, HttpOnly and SameSite=Lax; tokens are opaque and stored hashed
in the app database. Google/Supabase access and refresh tokens are not persisted.
Local `npm start` keeps the single-user offline mode unless AUTH_REQUIRED=true;
hosted auth requires HTTPS. Do not disable AUTH_REQUIRED on a public deployment.

## 5. Verify

1. Open the Render URL and sign in with Google.
2. Open the workspace and analyze a bundled demo capture.
3. Confirm the report loads; download JSON and PDF.
4. In Supabase Storage > captures, confirm a UUID-named `.capture` object exists.
5. Restart the Render service, reopen the saved analysis, and
   download its original capture. This confirms both database and file persistence.
6. Sign in with a second Google account in an incognito window. Its history must
   be empty. A direct URL to the first account's analysis, capture or export must
   return 404. Sign out and confirm those URLs require sign-in (401).

## Limits and troubleshooting

- Free Render sleeps after 15 idle minutes and wakes on a request, typically in
  about a minute. Supabase Free pauses after a week of inactivity.
- Stay within both providers' free usage quotas. Avoid adding paid resources;
  Render without a payment method suspends service/builds rather than charging
  overages when the documented free bandwidth/build limits are exceeded.
- Free-instance memory suitability is not yet measured. Start with the small
  bundled captures and one analysis at a time; large captures can exhaust memory.
- Authentication failures at startup: check the encoded database password and
  use the Session pooler address (5432), not the direct IPv6 endpoint.
- Upload returns 503: verify the private `captures` bucket, project URL, service
  role JWT, bucket limit, and whether Supabase is paused or over quota.
- Old local data is not copied by deployment. Unowned pre-login records stay
  hidden; do not assign them to the first user who signs in.
- Download links signed by Storage expire after 60 seconds. A recipient of an
  already issued signed link can use it until it expires, even after sign-out.
- To revoke an application's sessions administratively, delete that user's rows
  from user_sessions. Supabase account revocation does not immediately invalidate
  these eight-hour app sessions.

References:
- https://render.com/docs/docker
- https://render.com/docs/free
- https://supabase.com/docs/guides/database/connecting-to-postgres
- https://supabase.com/docs/guides/storage/security/access-control
- https://supabase.com/pricing
- https://supabase.com/docs/guides/auth/social-login/auth-google
- https://supabase.com/docs/guides/auth/redirect-urls
