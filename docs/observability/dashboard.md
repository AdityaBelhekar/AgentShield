# Dashboard

## Start the Backend

From the repository root:

```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

## Start the Frontend

From `frontend/`:

```bash
npm install
npm run dev
```

## Screenshot

!!! info "Screenshot coming soon"
    The React console renders event timelines, threat breakdowns, and forensic drill-down panels.

## WebSocket Endpoint

- Endpoint: `ws://localhost:8000/ws/events`
- Initial envelope types:
  - `connected`
  - `history` (recent event burst)
  - `event` (live stream)
  - `error`

The backend pushes the most recent history first, then streams new events in real time.