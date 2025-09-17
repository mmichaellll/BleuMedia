# BleuMedia

Small Flask app to upload, tag and watch video files. Uses SQLite (media.db) and SQLAlchemy for persistence, FFmpeg to generate thumbnails and the TMDB API (optional) to fetch posters.

## Features
- User registration / login
- Upload multiple video files (mp4, mov, avi, webm)
- Auto-generate thumbnails via FFmpeg or upload custom thumbnail
- Tagging, search and sorting in a user library
- Per-user media isolation (simple session-based auth)
- Optional TMDB poster import (set API key)

## Requirements
- Python 3.10+
- FFmpeg (required for thumbnail generation)
- Unix-like OS (dev container: Ubuntu 24.04.2 LTS)

Install Python deps:
```sh
pip install -r requirements.txt
```

Install FFmpeg (Ubuntu):
```sh
sudo apt update
sudo apt install -y ffmpeg
```

## Environment
Create a `.env` file in the project root for optional settings:

```
APIKEY=<your_tmdb_api_key>  # optional, used by /media_info
```

Note about Flask secret key:
- The app now generates a runtime secret with `secrets.token_urlsafe(32)` at startup, so you don't need to provide a secret for local development.
- For production or to preserve sessions across restarts, set a stable secret yourself (e.g. via an environment variable) or modify `app.secret_key` before deploying.

## Run (development)
Make sure `.env` exists (if using TMDB) and FFmpeg is installed.

```sh
python app.py
```

Open in browser from the dev container host:
```sh
"$BROWSER" http://localhost:5000
```

## Database & Storage
- SQLite file: `media.db` (created automatically)
- Upload temporary folder: `temp/`
- Final upload folder: `uploads/` (thumbnails saved under `uploads/thumbnails/`)

These directories are created automatically when uploading.

## Useful Routes
- `/` — landing page
- `/register`, `/login`, `/logout`
- `/dashboard` — user dashboard
- `/upload` — upload flow and temp queue
- `/library` — list / search / filter user media
- `/watch/<media_id>` — watch a video
- `/media_info/<media_id>` — view metadata and import TMDB poster
- `/profile` — update username/email/password

## Notes & Caveats
- Passwords are salted+hashed with SHA-256 (custom implementation). Replace with bcrypt / passlib for production.
- Do NOT run with `debug=True` in production. The app runs with debug mode when launched via `python app.py`.
- TMDB API key is optional; the app handles API failures gracefully.
- File handling and subprocess usage assume a trusted environment. Be cautious when exposing the app publicly.
- The app generates a random secret at startup (good for local/dev work). Use a fixed secret in production to maintain session continuity.

## Development
- Single-file Flask app: `app.py`.
- Templates and static files should live in `templates/` and `static/` respectively.