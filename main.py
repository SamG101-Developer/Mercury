from argparse import ArgumentParser
from threading import Thread


def main():
    # Create the argument parser
    parser = ArgumentParser()

    # Either run as server or client (must choose one)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--server", action="store_true", help="Run the application as a server.")
    group.add_argument("--client", action="store_true", help="Run the application as a client.")

    # Parse the arguments
    args = parser.parse_args()

    # Run the server or client
    if args.server:
        from ServerConnectionManager import ServerConnectionManager
        run(ServerConnectionManager)
    else:
        from ClientConnectionManager import ClientConnectionManager
        run(ClientConnectionManager)


def run(instance: type):
    Thread(target=instance).start()


if __name__ == "__main__":
    main()
