from __future__ import annotations

import argparse
from dataclasses import replace
import sys

from gateway.config import ConfigError, LoggingConfig, load_config
from gateway.logging import GatewayLogger, LoggerOptions, color_enabled
from gateway.server import run_gateway


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run Private Inference Gateway.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--config",
        default="config/gateway.dev.json",
        help="Path to gateway JSON config.",
    )
    parser.add_argument(
        "--log-file",
        help="Write access logs to a .log file.",
    )
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        help="Control colored CLI output.",
    )
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        logger = GatewayLogger(LoggerOptions(color=color_enabled("always")))
        logger.error(f"configuration error: {exc}")
        return 2

    if args.log_file or args.color:
        config = replace(
            config,
            logging=LoggingConfig(
                color=args.color or config.logging.color,
                file=args.log_file or config.logging.file,
            ),
        )

    logger = GatewayLogger(
        LoggerOptions(
            color=color_enabled(config.logging.color),
            file_path=config.logging.file,
        )
    )
    run_gateway(config, logger)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
