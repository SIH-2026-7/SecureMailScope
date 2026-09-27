# Free deployment: Render + Supabase

This setup serves the frontend and API together, uses PostgreSQL for reports, and
stores original captures in a private Supabase Storage bucket. It is a shared,
password-protected demo, not a multi-tenant service. Existing local analyses are
not migrated. Render can interrupt in-progress analysis on restart; reupload then.

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
6. Disable the project's Data API in its Data API settings if you do not need it
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
git add Dockerfile.render DEPLOYMENT.md backend/app/main.py backend/app/models/db_models.py backend/app/core/capture_storage.py backend/app/api/routes_upload.py backend/app/api/routes_analysis.py backend/tests/test_hosted_deployment.py
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
| `DEMO_USERNAME` | `demo` |
| `DEMO_PASSWORD` | A strong shared demo password |
| `OMP_NUM_THREADS` | `1` |
| `OPENBLAS_NUM_THREADS` | `1` |

Click Deploy Web Service. The first build installs Node/Python dependencies and
TShark. Tables are created automatically at startup. Do not add a paid disk or
Render PostgreSQL instance.

## 4. Verify

1. Open the Render URL and sign in using DEMO_USERNAME / DEMO_PASSWORD.
2. Open the workspace and analyze a bundled demo capture.
3. Confirm the report loads; download JSON and PDF.
4. In Supabase Storage > captures, confirm a UUID-named `.capture` object exists.
5. Restart the Render service, sign back in, reopen the saved analysis, and
   download its original capture. This confirms both database and file persistence.

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
- Old local data is not copied by deployment. Shared credentials grant access to
  every hosted capture/report; use synthetic captures for a shared demo.

References:
- https://render.com/docs/docker
- https://render.com/docs/free
- https://supabase.com/docs/guides/database/connecting-to-postgres
- https://supabase.com/docs/guides/storage/security/access-control
- https://supabase.com/pricing
