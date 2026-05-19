import socket
import logging
from typing import Optional


class OpenVPNManagementClient:
    """
    Client for connecting to OpenVPN management interface.
    Supports both Unix domain sockets and TCP sockets.
    """

    def __init__(
        self,
        socket_path: Optional[str] = None,
        host: str = "localhost",
        port: int = 7505,
    ):
        """
        Initialize the OpenVPN management client.

        Args:
            socket_path: Path to Unix domain socket (e.g., '/var/run/openvpn.sock')
            host: TCP hostname (if using TCP socket)
            port: TCP port (if using TCP socket)
        """
        self.socket_path = socket_path
        self.host = host
        self.port = port
        self.sock = None
        self.buffer_size = 4096
        self.connected = False

        # Setup logging
        self.logger = logging.getLogger(__name__)

    def connect(self) -> bool:
        """
        Connect to the OpenVPN management interface.

        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            if self.socket_path:
                # Connect via Unix domain socket
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(self.socket_path)
                self.logger.info(f"Connected to Unix socket: {self.socket_path}")
            else:
                # Connect via TCP socket
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((self.host, self.port))
                self.logger.info(f"Connected to TCP socket: {self.host}:{self.port}")

            if (
                not self.sock.recv(4096)
                .decode("utf-8", errors="ignore")
                .startswith(">INFO:")
            ):
                self.logger.error(
                    "Did not receive expected welcome message,disconnecting!"
                )
                self.disconnect()
                return False

            self.connected = True

            # # Read welcome message
            # welcome = self._receive_response()
            # self.logger.debug(f"Welcome message: {welcome}")

            return True

        except (socket.error, ConnectionRefusedError) as e:
            self.logger.error(f"Connection failed: {e}")
            self.connected = False
            return False

    def _send_command(self, command: str) -> None:
        """
        Send a command to the OpenVPN management interface.

        Args:
            command: Command string to send
        """
        if not self.connected or not self.sock:
            raise ConnectionError("Not connected to OpenVPN management interface")

        # Commands must end with newline
        if not command.endswith("\n"):
            command += "\n"

        self.sock.sendall(command.encode("utf-8"))
        self.logger.debug(f"Sent command: {command.strip()}")

    def _receive_response(self, timeout: Optional[float] = None) -> str:
        """
        Receive response from the OpenVPN management interface.

        Args:
            timeout: Optional timeout in seconds

        Returns:
            str: Response from OpenVPN
        """
        if not self.connected or not self.sock:
            raise ConnectionError("Not connected to OpenVPN management interface")

        if timeout:
            self.sock.settimeout(timeout)

        try:
            response = b""
            while True:
                chunk = self.sock.recv(self.buffer_size)
                if not chunk:
                    break
                response += chunk
                # OpenVPN ends responses with END marker or newline
                if (
                    b"\nEND" in response[-10:]
                    or b"\nSUCCESS: " in response
                    or b"\nERROR: " in response
                ):
                    break

            return response.decode("utf-8", errors="ignore").strip()

        except socket.timeout:
            self.logger.warning("Socket timeout while receiving response")
            return ""

    def send_command(self, command: str, timeout: Optional[float] = 5.0) -> str:
        """
        Send a command and receive the response.

        Args:
            command: Command to send
            timeout: Response timeout in seconds

        Returns:
            str: Response from OpenVPN
        """
        self._send_command(command)
        return self._receive_response(timeout)

    def disconnect_client_by_cn(self, common_name: str) -> str:
        """
        Disconnect a client by their Common Name (CN) using the kill command.

        Args:
            common_name: Client's Common Name (CN) to disconnect

        Returns:
            str: Response from OpenVPN

        Note:
            The 'kill' command requires the management interface to be in client mode
            or for the server to have client management enabled.
        """
        # Format: kill common_name
        command = f"kill {common_name}"
        return self.send_command(command)

    def list_clients(self) -> str:
        """
        Get list of connected clients (if supported by OpenVPN version).

        Returns:
            str: Client list or status
        """
        return self.send_command("status 2")

    def get_version(self) -> str:
        """
        Get OpenVPN version information.

        Returns:
            str: Version information
        """
        return self.send_command("version")

    def disconnect(self) -> None:
        """
        Disconnect from the OpenVPN management interface.
        """
        if self.sock:
            try:
                # Send quit command to gracefully close the management session
                self._send_command("quit")
            except:
                pass

            self.sock.close()
            self.sock = None
            self.connected = False
            self.logger.info("Disconnected from OpenVPN management interface")

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()


# Example usage
def example_usage():
    """
    Example demonstrating how to use the OpenVPNManagementClient class.
    """
    import time

    # Setup basic logging
    logging.basicConfig(level=logging.INFO)

    # Example 1: Using Unix domain socket
    print("=== Example 1: Using Unix Socket ===")
    try:
        with OpenVPNManagementClient(socket_path="/var/run/openvpn.sock") as client:
            # Get version info
            version = client.get_version()
            print(f"OpenVPN Version: {version}")

            # List connected clients
            status = client.list_clients()
            print(f"Status:\n{status}")

            # Disconnect a specific client by CN
            # Uncomment the line below when you need to disconnect a client
            # response = client.disconnect_client_by_cn("client_common_name")
            # print(f"Kill response: {response}")

            # Small delay to see responses
            time.sleep(1)
    except Exception as e:
        print(f"Unix socket error: {e}")

    print("\n")

    # Example 2: Using TCP socket
    print("=== Example 2: Using TCP Socket ===")
    try:
        with OpenVPNManagementClient(host="localhost", port=7505) as client:
            # Test connection with version command
            version = client.get_version()
            print(f"OpenVPN Version: {version}")

            # You can also manually control connection
            # client = OpenVPNManagementClient(host='localhost', port=7505)
            # if client.connect():
            #     result = client.disconnect_client_by_cn("some_client")
            #     print(f"Disconnect result: {result}")
            #     client.disconnect()

    except Exception as e:
        print(f"TCP socket error: {e}")


# Security considerations note
# SECURITY_NOTE = """
# SECURITY CONSIDERATIONS:
# 1. The OpenVPN management interface does NOT use encryption
# 2. Always bind to localhost (127.0.0.1) or use Unix domain sockets
# 3. Restrict access using --management-client-user and --management-client-group
# 4. Consider using the management interface password protection
# 5. Never expose the management interface to external networks
# """

# if __name__ == "__main__":
#     print(SECURITY_NOTE)
#     example_usage()
