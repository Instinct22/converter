"""Доставка агрегированных метрик Master, включая смену приёмника в панели."""
import os
import subprocess
import time
from pathlib import Path

from sqlalchemy.exc import OperationalError
from sqlmodel import Session

from app.database import engine
from app.exporters import grafana_target
from app.fleet_metrics import scrape_key


def main():
    os.umask(0o077)
    config = Path('/tmp/master-scrape.yml')
    config.write_text("""global:
  scrape_interval: 15s
scrape_configs:
  - job_name: master-host
    static_configs:
      - targets: ['master-host:9100']
        labels:
          node: Master
  - job_name: master-fleet
    metrics_path: /monitoring/master.prom
    bearer_token_file: /tmp/master-read-token
    static_configs:
      - targets: ['xui-master:8080']
""")
    process = None
    active = None
    while True:
        try:
            with Session(engine) as session:
                target = grafana_target(session)
        except (ValueError, OperationalError):
            time.sleep(15)
            continue
        if process is None or process.poll() is not None or active != target:
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=30)
            url, token = target
            Path('/tmp/master-write-token').write_text(token)
            Path('/tmp/master-read-token').write_text(scrape_key(token))
            process = subprocess.Popen([
                '/usr/local/bin/vmagent', '-httpListenAddr=127.0.0.1:8429',
                f'-promscrape.config={config}', f'-remoteWrite.url={url}',
                '-remoteWrite.bearerTokenFile=/tmp/master-write-token',
                '-remoteWrite.forcePromProto=true', '-remoteWrite.tmpDataPath=/queue',
                '-remoteWrite.maxDiskUsagePerURL=256MB',
            ])
            active = target
        time.sleep(15)


if __name__ == '__main__':
    main()
