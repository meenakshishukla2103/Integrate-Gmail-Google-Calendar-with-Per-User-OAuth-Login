# Google OAuth Project

## Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Copy `.env.example` to `.env` and add your Google OAuth credentials.

3. Run the project:
   ```
   python start_server.py
   ```

4. Open http://localhost:3000 in your browser.

## Files

- `main.py` - main application
- `start_server.py` - starts the server
- `public/` - login and dashboard pages
- `database.db` - created automatically when you run the app

## Environment Variables

- `GOOGLE_CLIENT_ID` - Google OAuth Client ID
- `GOOGLE_CLIENT_SECRET` - Google OAuth Client Secret
- `GOOGLE_REDIRECT_URI` - callback URL (default: http://localhost:3000/auth/google/callback)
- `SESSION_SECRET` - secret key for sessions
- `PORT` - server port (default: 3000)
- `DB_FILE` - database file name (default: database.db)
