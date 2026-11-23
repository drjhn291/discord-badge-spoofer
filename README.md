# discord-badge-spoofer

Inflates your Discord profile badges by adding custom hours played and marking verified games as played.

> **Important Notice — Processing Delay:** Hours played and games-played counts **do not update instantly**. Discord processes telemetry asynchronously on its analytics cycle, so it may take **several hours or up to 1–2 days** for the new hours and games to show up on your profile and badges.

## How It Works

Discord's analytics endpoint (`/api/v9/science`) tracks which games you launch and how long you play them. This tool replicates the exact event flow of the official desktop client (`launch_game` and `running_game_heartbeat`), letting you specify custom playtime durations and game counts. Discord accepts the batches (`HTTP 204`), and the activity is credited toward your profile badges.

- **Status:** Verified working and currently unpatched.
- **Sync Delay:** Expect a delay—it can take **from a few hours up to 1–2 days** for Discord to update your hours played and games-played badges after running the tool. Do not spam batches thinking it failed if you don't see changes right away.
- **Privacy:** Your token, cookie, and fingerprint are stored locally in `client_state.json`—nothing is sent anywhere except Discord's official endpoints (and `cordapi.dolfi.es` to fetch current client build properties).
- **Terms of Service:** Automating user accounts violates Discord's Terms of Service and may break if Discord patches the endpoint. Use it only on accounts you are comfortable losing.

## Setup

No third-party dependencies required—built with the pure Python standard library (**Python 3.10+**).

1. **Clone the repository:**
   ```bash
   git clone https://github.com/drjhn291/discord-badge-spoofer.git
   cd discord-badge-spoofer
   ```

2. **Run the script:**
   ```bash
   python spoofer.py
   ```

3. **Enter your Discord account token:**
   On the first run, paste your account token when prompted. It gets saved to `client_state.json` and reused automatically. Your `analytics_token` is fetched automatically via `GET /users/@me?with_analytics_token=true`.

4. **Enter your cookie (`cf_clearance`):**
   On startup, paste your full `Cookie` header (containing `cf_clearance=...`) grabbed from any `/science` request in your browser or client Developer Tools (`Network` tab). It is saved to `client_state.json` and can be updated anytime via menu option `2`.

5. **Optional — Set `executable_fingerprint` (Windows):**
   The fingerprint is not strictly required for playtime hours, and some users report getting the games-played badge without it. However, to maximize reliability for the **games-played** count, select menu option `3` and provide the path to any installed 64-bit game `.exe` (or active process PID) to generate a valid fingerprint automatically.

## Menu

- **`[1]` Claim playtime & games** — Asks how many verified Windows games to process and how many hours to credit per game.
- **`[2]` Update cookie / refresh session** — Pulls a fresh `analytics_token`, rotates session UUIDs, and lets you paste a new `cf_clearance` cookie.
- **`[3]` Generate executable_fingerprint (Windows)** — Computes a valid PE/Authenticode `executable_fingerprint` bound to your account ID and machine GUID.
- **`[4]` Exit** — Closes the application.

## How Auth Works

- **`token`** — Your Discord account token, entered on first run and saved locally to `client_state.json`.
- **`analytics_token`** — Fetched automatically from `GET /users/@me?with_analytics_token=true` and cached for 12 hours.
- **`super_props` / `heartbeat` / `launch` IDs** — Generated automatically on every session start.
- **`cookie` (`cf_clearance`)** — Pasted manually on setup or refreshed anytime via option `2`.
- **`fingerprint`** — Optional, recommended for the games-played badge count (see below).

## About the Fingerprint & Delays

- **Be patient:** Even when Discord returns `204` (accepted), your profile will not update immediately. Both **hours played** and **games played** can take **up to 24–48 hours** to appear.
- **Playtime hours** work with just your `token` and `cookie`.
- **Games-played count** may require a valid `executable_fingerprint`. You can test running the tool without it first; if the game count has not updated after 1–2 days, use option `3` on Windows (pointing it to any valid 64-bit `.exe` or running game PID), or manually paste a captured `executable_fingerprint` from a real `launch_game` request in DevTools into `client_state.json`:

```json
{
  "fingerprint": "Ab5ekw..."
}
```

## Disclaimer

This tool violates Discord's Terms of Service. Use it at your own risk and only on accounts you are fine losing. Provided as-is with no warranty.

## License

Released under the MIT License. See [LICENSE](LICENSE).
