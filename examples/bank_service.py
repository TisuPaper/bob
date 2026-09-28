"""Synthetic banking service with three deliberately planted logging leaks."""
from dataclasses import dataclass
import logging
from pii_guard.runtime import JsonFormatter

logger = logging.getLogger("demo.bank")


@dataclass
class Customer:
    email: str
    ic: str
    card: str
    account: str


def notify(customer):
    logger.info("Email: %s", customer.email)
    return True


def process(customer):
    logger.info("Processing %s", customer)
    return "processed"


def transfer(customer):
    try:
        raise ValueError(f"Rejected request account={customer.account}; email={customer.email}")
    except ValueError as exc:
        logger.error("Transfer failed: %s", exc)
    return "rejected"


def run(log_path):
    handler = logging.FileHandler(log_path, mode="w", encoding="utf-8")
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        customer = Customer("demo.customer@example.test", "900101-14-5678", "4111111111111111", "1234567890")
        return [notify(customer), process(customer), transfer(customer)]
    finally:
        logger.removeHandler(handler)
        handler.close()


if __name__ == "__main__":
    import sys
    run(sys.argv[1] if len(sys.argv) > 1 else "test-run.jsonl")
