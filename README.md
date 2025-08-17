# MAIAS Demo (Multi-Agent Orchestration)

A Next.js demo web app that simulates a multi-agent workflow across different operational scenarios (DevOps, Security Triage, Data Publish, IT Onboarding).

## Local Development

```bash
npm install   # or pnpm/yarn
npm run dev   # http://localhost:3000
```

## Deploying to Vercel

1. Push this repo to GitHub.
2. Create a new project on Vercel and import the repo.
3. Framework preset: Next.js (auto-detected)
4. Build command: `next build` (default)
5. Output directory: `.next` (default)
6. Environment variables (optional for live mode):
   - `OPENAI_API_KEY`

## Project Structure

- `app/` Route handlers and pages (Next.js App Router)
- `app/page.tsx` Main demo UI and simulation logic
- `app/layout.tsx` Global layout
- `app/globals.css` Tailwind entry
- `tailwind.config.ts` Tailwind config

## Notes

- The app runs entirely client-side in demo mode; no server functions are required.
- Toggle Demo/Live switch in the UI. Live mode expects `OPENAI_API_KEY` to be present.
