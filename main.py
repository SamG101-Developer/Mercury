from argparse import ArgumentParser
from threading import Thread
import sys

from PyQt6.QtWidgets import QApplication


def main():
    # Create the argument parser
    parser = ArgumentParser(description="Run the application as a server or client.")

    # Either run as server or client (must choose one)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--server", action="store_true", help="Run the application as a server.")
    group.add_argument("--client", action="store_true", help="Run the application as a client.")

    # Parse the arguments
    args = parser.parse_args()

    # Run the server or client
    if args.server:
        from src.ServerConnectionManager import ServerConnectionManager
        run(ServerConnectionManager)
    else:
        from src.ClientConnectionManager import ClientConnectionManager
        run(ClientConnectionManager)


def run(instance: type):
    application = QApplication(sys.argv)
    instance()
    sys.exit(application.exec())


if __name__ == "__main__":
    main()
