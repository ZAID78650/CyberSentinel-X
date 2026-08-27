# OAuth Setup Guide — CyberSentinel X

## Google OAuth (Production Mode)

### Step 1: Create Google Cloud Project
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click **Select a project** → **New Project**
3. Name it `CyberSentinel X` → Click **Create**
4. Wait for creation, then select the project

### Step 2: Configure OAuth Consent Screen
1. Go to **APIs & Services** → **OAuth consent screen**
2. Select **External** user type → Click **Create**
3. Fill in:
   - **App name**: `CyberSentinel X`
   - **User support email**: your email
   - **Developer contact**: your email
4. Click **Save and Continue**
5. **Scopes**: Click **Add or Remove Scopes** → Select `openid`, `email`, `profile` → **Update** → **Save and Continue**
6. **Test users**: Add your Google email → **Save and Continue**
7. Click **Back to Dashboard**

### Step 3: Create OAuth Credentials
1. Go to **APIs & Services** → **Credentials**
2. Click **+ Create Credentials** → **OAuth client ID**
3. Application type: **Web application**
4. Name: `CyberSentinel X`
5. **Authorized redirect URIs** → Click **Add URI**:
   ```
   http://localhost:5174/api/auth/oauth/google/callback
   ```
6. Click **Create**
7. Copy the **Client ID** and **Client Secret**

### Step 4: Update `.env`
Edit `backend/.env` and add:
```bash
GOOGLE_CLIENT_ID=your-client-id-here.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret-here
```

### Step 5: Restart Backend
```bash
cd /Users/zaidshaikhmohammad/Desktop/cybersentinel-x/backend
screen -X -S csx-backend quit 2>/dev/null
source .venv/bin/activate
screen -dmS csx-backend python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## GitHub OAuth (Production Mode)

### Step 1: Create GitHub OAuth App
1. Go to [GitHub Settings → Developer settings → OAuth Apps](https://github.com/settings/developers)
2. Click **New OAuth App**
3. Fill in:
   - **Application name**: `CyberSentinel X`
   - **Homepage URL**: `http://localhost:5174`
   - **Authorization callback URL**:
     ```
     http://localhost:5174/api/auth/oauth/github/callback
     ```
4. Click **Register application**
5. Copy the **Client ID**
6. Click **Generate a new client secret** → Copy the **Client Secret** (shown only once!)

### Step 2: Update `.env`
Edit `backend/.env` and add:
```bash
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

### Step 3: Restart Backend
```bash
cd /Users/zaidshaikhmohammad/Desktop/cybersentinel-x/backend
screen -X -S csx-backend quit 2>/dev/null
source .venv/bin/activate
screen -dmS csx-backend python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## Testing

After setup, the login page will show **"SSO is configured — click to sign in"** instead of the demo mode message.

Click **Google** or **GitHub** → redirected to provider → authorize → redirected back → logged in!

### Production Deployment
For production, update the redirect URIs in Google Cloud Console / GitHub OAuth App to use your production domain:
- Google: `https://yourdomain.com/api/auth/oauth/google/callback`
- GitHub: `https://yourdomain.com/api/auth/oauth/github/callback`
- Update `FRONTEND_URL` in `.env` to `https://yourdomain.com`
