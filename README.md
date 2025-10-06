# Serverless "Find My Device" Backend on Cloudflare Workers

This project is a serverless backend built on Cloudflare Workers designed to support a "Find My Device" style Android application. It handles secure authentication with Google APIs using a service account, generates Firebase Cloud Messaging (FCM) access tokens, and uses Cloudflare D1 for persistent data storage.

The primary function is to provide a secure and scalable infrastructure for an Android app to send and receive location data and other commands via FCM push notifications.

## Core Features
- **Serverless Architecture:** Runs on the globally distributed Cloudflare network for low latency and high availability without managing servers.
- **Secure Google API Authentication:** Uses a service account's private key to generate JWTs and securely obtain OAuth2 access tokens for Google APIs.
- **FCM Token Management:** Caches and refreshes Google access tokens, storing them securely in a Cloudflare D1 database to efficiently send push notifications.
- **Persistent Data Storage:** Leverages Cloudflare D1 to store user FCM tokens, location history, and the latest known device location.
- **Simple API Interface:** Provides a set of clear API endpoints for an Android client to interact with.

## API Endpoints

All endpoints require specific headers for authentication and data payload.

### Required Headers:
- `apiKey`: A secret API key to authorize the request.
- `user`: The unique identifier for the user/device.

### 1. Send Data / Command
Sends a JSON payload to a user's device via FCM.

**Endpoint:** `/sendData`  
**Headers:**
- `apiKey`: YourSendDataAPIKey
- `user`: The target user ID to send the notification to.
- `value`: A JSON string representing the data to be sent.

### 2. Get Last Known Location
Retrieves the most recently stored location for a given user.

**Endpoint:** `/getLastLocation`  
**Headers:**
- `apiKey`: YourGetLocationAPIKey
- `user`: The user ID whose location is being requested.

### 3. Update Last Known Location
Allows a device to push its current location to the server.

**Endpoint:** `/updateLastLocation`  
**Headers:**
- `apiKey`: YourUpdateLocationAPIKey
- `user`: The user ID of the device sending its location.
- `location`: A string representing the coordinates (e.g., "latitude,longitude").

### 4. Refresh FCM Token
Updates the FCM registration token for a specific user.

**Endpoint:** `/tokenRefresh`  
**Headers:**
- `apiKey`: YourTokenRefreshAPIKey
- `user`: The user ID whose token is being updated.
- `fcmToken`: The new FCM registration token.

## Setup and Deployment

### Prerequisites
- A Cloudflare account
- Node.js and npm installed
- Cloudflare's Wrangler CLI (`npm install -g wrangler`)

### Step-by-Step Guide

#### Google Cloud & Service Account Setup
1. Create a new project in the [Google Cloud Console](https://console.cloud.google.com/).
2. Enable the **Firebase Cloud Messaging API**.
3. Create a **Service Account** and grant it the **Firebase Cloud Messaging API Admin** role.
4. Generate a **JSON key** for this service account and download it securely.

#### Cloudflare D1 Setup
1. In your Cloudflare dashboard, go to **Workers & Pages > D1**.
2. Create a new database.
3. Define tables to store tokens, OAuth credentials, and user locations.
4. Note the database binding details.

#### Project Configuration
1. Clone this repository.
2. Update your `wrangler.toml`:

```toml
[[d1_databases]]
binding = "DB" # Must match binding in code (env.DB)
database_name = "your-database-name"
database_id = "your-database-id"
```

#### Manage Secrets with Wrangler
Use Wrangler secrets to securely store credentials.

```bash
wrangler secret put SERVICE_ACCOUNT_JSON
wrangler secret put SEND_DATA_API_KEY
wrangler secret put GET_LOCATION_API_KEY
wrangler secret put UPDATE_LOCATION_API_KEY
wrangler secret put TOKEN_REFRESH_API_KEY
```

#### Deploy the Worker
```bash
wrangler deploy
```

## Security Considerations
- **Credential Management:** Never commit secrets to version control.
- **API Key Rotation:** Regularly rotate API keys used by clients.
- **Least Privilege:** Grant minimal necessary permissions to the Google Service Account.

## License
This project is licensed under the **MIT License**. See the `LICENSE` file for details.
