from argparse import ArgumentParser

from src.ServerConnectionManager import ServerConnectionManager
from src.ClientConnectionManager import ClientConnectionManager


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
        run(ServerConnectionManager)
    else:
        run(ClientConnectionManager)


def run(instance: type):
    instance()

    # Do nothing for the server. The client has its own command interface constantly being listened to.
    while instance == ServerConnectionManager:
        pass


if __name__ == "__main__":
    main()
