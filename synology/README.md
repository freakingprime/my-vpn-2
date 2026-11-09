# Deploying my-vpn-2 on Synology Container Manager

A complete guide for deploying **my-vpn-2** on an x86_64 Synology NAS (e.g., DS220+) running DSM 7.2+ **Container Manager**, pulling directly from GitHub Container Registry (`ghcr.io/freakingprime/my-vpn-2:latest`).

---

## 1. Directory Structure on Synology NAS

In Synology **File Station**, create `/volume1/docker/my-vpn-2`:

```text
/volume1/docker/
└── my-vpn-2/
    ├── docker-compose.yml       <-- From synology/docker-compose.yml
    ├── .env                     <-- Environment configuration (ports & SSH target)
    ├── id_rsa                   <-- SSH private key (OpenSSH PEM format, chmod 600)
    ├── custom.conf              <-- Auto-managed standby config for Gluetun
    └── exit_history.json        <-- Auto-managed state file
```

---

## 2. Configuration Files

### A. Environment File: `/volume1/docker/my-vpn-2/.env`

Create `.env` inside `/volume1/docker/my-vpn-2/` (based on the root `.env.example`):

```env
WEB_PORT=8080
PROXY_PORT=8888
GCE_HOST=203.0.113.10:22
GCE_USER=cloud-user
GCE_KEY_PATH=/data/id_rsa
```

### B. Compose File: `/volume1/docker/my-vpn-2/docker-compose.yml`

Use [`synology/docker-compose.yml`](docker-compose.yml), which pulls `ghcr.io/freakingprime/my-vpn-2:latest` and `qmcgaw/gluetun:latest`.

---

## 3. Step-by-Step Setup in Synology DSM

### Step 1: Ensure Synology TUN Driver is Loaded
Gluetun requires the Linux TUN kernel driver (`/dev/net/tun`).
1. Open DSM **Control Panel** $\rightarrow$ **Task Scheduler**.
2. Click **Create** $\rightarrow$ **Triggered Task** $\rightarrow$ **User-defined script**:
   - **Task Name**: `Load TUN Driver`
   - **User**: `root`
   - **Event**: `Boot-up`
   - **Run command**:
     ```bash
     if [ ! -c /dev/net/tun ]; then
         insmod /lib/modules/tun.ko
     fi
     ```
3. Click **OK**, right-click the task, and select **Run**.

### Step 2: Upload Files & Grant Permissions
1. Upload `docker-compose.yml`, `.env`, and your SSH private key into `/volume1/docker/my-vpn-2/`.
2. Right-click `/volume1/docker/my-vpn-2` in **File Station** $\rightarrow$ **Properties** $\rightarrow$ **Permission** tab:
   - Click **Create** $\rightarrow$ User: **`Everyone`** $\rightarrow$ Type: **Allow** $\rightarrow$ Permission: **Read & Write** (Full Control).
   - Check **Apply to this folder, sub-folders and files** $\rightarrow$ Click **Save**.

### Step 3: Create and Start the Project
1. Open **Container Manager** $\rightarrow$ **Project** $\rightarrow$ **Create**:
   - **Project Name**: `my-vpn-2`
   - **Path**: Select `/docker/my-vpn-2`
   - **Source**: Select **Use existing docker-compose.yml**
2. Click **Next** $\rightarrow$ **Done**. Container Manager will automatically pull `ghcr.io/freakingprime/my-vpn-2:latest` and start the containers.

---

## 4. Verification & Updating

- **Web Control Panel**: `http://<YOUR_NAS_IP>:<WEB_PORT>`
- **HTTP/HTTPS Proxy**: `<YOUR_NAS_IP>:<PROXY_PORT>`
- **PAC Auto-Config URL**: `http://<YOUR_NAS_IP>:<WEB_PORT>/proxy.pac`

### Updating to the Latest Image
Because `pull_policy: always` is configured in `docker-compose.yml`, Container Manager will automatically check GitHub Container Registry and download the newest image whenever you build:
1. Open DSM **Container Manager** $\rightarrow$ **Project**.
2. Select `my-vpn-2` $\rightarrow$ Click **Action** $\rightarrow$ **Stop**.
3. Click **Action** $\rightarrow$ **Build** (or **Clean** then **Build**).
4. Container Manager will automatically pull the newest `:latest` image from `ghcr.io` and start the updated container.
