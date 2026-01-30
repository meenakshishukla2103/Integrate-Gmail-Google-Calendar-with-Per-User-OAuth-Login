import os
from dotenv import load_dotenv

load_dotenv()

from main import app

if __name__ == '__main__':
    port = int(os.getenv('PORT', 3000))
    debug = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    print(f"Starting server on http://localhost:{port}")
    print(f"Google OAuth callback URL: {os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:3000/auth/google/callback')}")
    app.run(host='0.0.0.0', port=port, debug=debug)
