# PhishWatch Deployment Guide

## Backend (Render.com)

1. Push the Django project folder to a GitHub repository
2. Go to https://render.com and sign up with GitHub
3. Click "New Web Service"
4. Connect your GitHub repository
5. Render will auto-detect render.yaml
6. Set these environment variables in the Render dashboard:
   - SECRET_KEY: generate one at https://djecrety.ir
   - SCREENSHOTLAYER_API_KEY: your key from screenshotlayer.com
   - DEBUG: False
7. Click Deploy
8. Wait for build to complete (3-5 minutes)
9. Your backend URL will be: https://phishwatch-api.onrender.com
10. Test it: open https://phishwatch-api.onrender.com/health/ in browser
    You should see: {"status": "ok", "model_loaded": true}

## Frontend (Netlify)

1. Go to https://netlify.com and sign up
2. Click "Add new site" → "Deploy manually"
3. Drag and drop the phisbusterv2 folder
4. Your site will be live at: https://random-name.netlify.app
5. Go to Site Settings → Domain → rename to phishwatch (or any name)
6. Your final URL: https://phishwatch.netlify.app

## After Both Are Deployed

1. Copy your actual Netlify URL
2. Open settings.py in your Django project
3. Replace "https://your-app-name.netlify.app" in CORS_ALLOWED_ORIGINS
   with your actual Netlify URL
4. Push the change to GitHub
5. Render will auto-redeploy

## Testing Production

1. Open your Netlify URL
2. Scan this URL: http://www.paypal.com.cgi-bin.webscr.update-account.info/
3. Confirm verdict, WHOIS panel, and screenshot all load correctly
