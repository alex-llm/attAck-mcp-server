# attAck-mcp-server

This project is an MCP (Model Context Protocol) server for querying ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) techniques and tactics. It provides a way to access and retrieve information about various attack techniques and tactics used by adversaries.

## Tools

The server provides the following tools:

*   **query\_technique:**  This tool allows you to query ATT&CK techniques by ID or name.
    *   **Arguments:**
        *   `technique_id` (string, optional): The ID of the technique to query.
        *   `tech_name` (string, optional): The name of the technique to query.
    *   **Example:**
        ```json
        {
          "technique_id": "T1059.001"
        }
        ```
*   **list\_tactics:** This tool allows you to retrieve a list of all ATT&CK tactics.
    *   **Arguments:** None

## Usage

To use this MCP server, you need to have an MCP client configured to connect to it. Once connected, you can use the provided tools to query ATT&CK techniques and tactics.

## Installation

1.  Clone this repository.
2.  Install the required dependencies using `pip install -r requirements.txt`.
3.  Configure the MCP server in your MCP client.

## ATT&CK

ATT&CK is a curated knowledge base and model for cyber adversary behavior, reflecting the various phases of an adversary’s attack lifecycle and the platforms they are known to target. ATT&CK is useful for understanding security risks against any specific technology or organization.
