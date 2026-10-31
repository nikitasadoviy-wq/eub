
import json
import logging
import time
from pathlib import Path

from core.process_guard import inspect_processes, get_cache_stats
from core.installer_guard import inspect_installers
from core.service_guard import inspect_services
from core.task_guard import inspect_scheduled_tasks


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config" / "settings.json"


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as file:
        return json.load(file)


def setup_logging(config):
    logging_config = config.get("logging", {})

    log_file = BASE_DIR / logging_config.get(
        "file", "logs/events.log"
    )

    log_file.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=getattr(
            logging,
            logging_config.get("level", "INFO").upper(),
            logging.INFO
        ),
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_file, encoding="utf-8")
        ],
        force=True
    )


def log_process_details(process):
    logging.info(
        "EDGE PROCESS: PID=%s NAME=%s TYPE=%s",
        process.get("pid"),
        process.get("name"),
        process.get("type")
    )

    logging.info("  PATH: %s", process.get("executable"))

    pe = process.get("pe", {})
    signature = process.get("signature", {})

    if pe.get("is_pe"):
        logging.info("  PE: VALID")
        logging.info("  PE TYPE: %s", pe.get("pe_type"))
        logging.info("  SHA256: %s", pe.get("sha256"))
        logging.info(
            "  PRODUCT: %s",
            pe.get("version_info", {}).get("ProductName", "Unknown")
        )
        logging.info(
            "  VERSION: %s",
            pe.get("version_info", {}).get("ProductVersion", "Unknown")
        )
    else:
        logging.warning(
            "  PE: NOT VERIFIED (%s)",
            pe.get("error", "Not a valid PE or analysis failed")
        )

    logging.info(
        "  SIGNATURE: %s",
        signature.get("Status", "UNKNOWN")
    )
    logging.info(
        "  SIGNER: %s",
        signature.get("Signer", "Unknown")
    )


def main():
    config = load_config()
    setup_logging(config)

    logging.info(
        "EUB v%s initialized",
        config.get("application", {}).get("version", "unknown")
    )

    monitoring = config.get("monitoring", {})

    if not monitoring.get("enabled", True):
        logging.info("Monitoring disabled. Exiting.")
        return

    interval = max(
        1,
        monitoring.get("interval_seconds", 2)
    )

    logging.info("Starting EUB scan")

    try:
        while True:
            processes = inspect_processes()
            installers = inspect_installers()
            services = inspect_services()
            tasks = inspect_scheduled_tasks()

            logging.info("Processes detected: %d", len(processes))
            logging.info("Installers detected: %d", len(installers))
            logging.info("Services checked: %d", len(services))
            logging.info("Scheduled tasks detected: %d", len(tasks))

            cache = get_cache_stats()
            logging.info(
                "CACHE: HITS=%d MISSES=%d ANALYZED_FILES=%d",
                cache["hits"],
                cache["misses"],
                cache["analyzed_files"]
            )

            for process in processes:
                log_process_details(process)

            time.sleep(interval)

    except KeyboardInterrupt:
        logging.info("EUB stopped by user")


if __name__ == "__main__":
    main()
