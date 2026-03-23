# SIEM-Lite: Cloud-Native Log Monitoring & Alerting System

[![Docker](https://img.shields.io/badge/Docker-Ready-blue)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-brightgreen)](https://www.python.org/)
[![Grafana](https://img.shields.io/badge/Grafana-Dashboard-orange)](https://grafana.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](./LICENSE)

## Quick Start

Get started with SIEM-Lite in just three commands:

```bash
git clone https://github.com/your-repo/siem-lite.git
cd siem-lite
docker compose up -d
```

Access the Grafana dashboard at `http://localhost:3000` (default credentials: `admin` / `admin`).

## Architecture

SIEM-Lite leverages the PLG stack for efficient log monitoring and alerting:

- **Promtail**: Collects and forwards logs.
- **Loki**: Aggregates and indexes logs.
- **Grafana**: Visualizes logs and alerts.

![PLG Stack Architecture](# "Add architecture diagram here")

## Detection Rules

SIEM-Lite uses YAML-based detection rules to identify signals of interest. Below is an example of the detection rules format:

| Rule                | Signal                  | Severity | Score |
|---------------------|-------------------------|----------|-------|
| Unauthorized Access | Failed login attempts   | High     | 90    |
| Data Exfiltration   | Large data transfers    | Critical | 95    |
| Malware Activity    | Suspicious file hashes  | Medium   | 70    |

## Screenshots

Add screenshots to showcase the system in action:

- **Grafana Dashboard**: ![Grafana Dashboard](<img width="925" height="460" alt="Grafana" src="https://github.com/user-attachments/assets/e7ed3c64-02be-407f-b267-d2e754acff07" />
)
- **Alert Output**: ![Alert Output](# "Add alert output screenshot here")

## Cloud Deployment

Run SIEM-Lite on your preferred cloud platform:

### AWS EC2

1. Launch an EC2 instance with Docker installed.
2. Clone the repository and start the services:

   ```bash
   git clone https://github.com/your-repo/siem-lite.git
   cd siem-lite
   docker compose up -d
   ```

3. Access the Grafana dashboard at `http://<EC2-Public-IP>:3000`.

### Azure VM

1. Create an Azure VM with Docker pre-installed.
2. Clone the repository and start the services:

   ```bash
   git clone https://github.com/your-repo/siem-lite.git
   cd siem-lite
   docker compose up -d
   ```

3. Access the Grafana dashboard at `http://<VM-Public-IP>:3000`.

## SDG Alignment

SIEM-Lite contributes to the following Sustainable Development Goals:

- **SDG 9**: Industry, Innovation, and Infrastructure
  - Promotes resilient infrastructure through robust log monitoring.
- **SDG 16**: Peace, Justice, and Strong Institutions
  - Enhances security and transparency by detecting and mitigating threats.

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository.
2. Create a feature branch.
3. Submit a pull request with a detailed description.

## License

This project is licensed under the [MIT License](./LICENSE).
