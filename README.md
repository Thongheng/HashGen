# HashGen - Universal Crypto Tool

**HashGen** is a flexible, modular cryptographic tool designed to generate hashes and signatures using user-defined Python algorithms. It features a modern, responsive GUI built with CustomTkinter and allows for valid runtime injection of custom logic.

## Features

*   **Dynamic Algorithm Support**: Write implementation logic in Python and execute it on the fly. No need to restart the application.
*   **Modern UI**: Dark-themed, responsive interface using `customtkinter`.
*   **Snippet Manager**: Save, Load, and Edit your custom algorithms in the built-in editor.
*   **Auto-Magic JSON**:
    *   **Auto-Format**: Pasting messy JSON payload automatically pretty-prints it.
    *   **Auto-Extract Keys**: Automatically extracts keys from the JSON payload to populate the "Keys Order" field.
*   **Standard Library Injection**: Algorithms have access to `hashlib`, `hmac`, `base64`, `json`, and `time` automatically.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/yourusername/HashGen.git
    cd HashGen
    ```

2.  Install dependencies:
    ```bash
    pip install customtkinter
    ```

## Usage

Run the main script:

```bash
python3 HashGen.py
```

### Generator Tab
1.  **Algorithm**: Select your desired algorithm from the dropdown.
2.  **PassCode**: Enter your secret key/IV string.
3.  **API Key**: (Optional) Enter an API key if required by your algorithm.
4.  **Keys Order**: Comma-separated list of keys from the JSON payload to include in the signature. (Auto-filled when you edit the JSON).
5.  **JSON Payload**: Enter the data to sign.
6.  **Output**: The generated hash will appear here.

### Snippet Editor
1.  **Name**: Give your algorithm a name.
2.  **Code**: Write your Python implementation.
3.  **Save/Load**: Persist your snippets to `snippets.json`.

## Writing Custom Algorithms

Your snippet **MUST** define a `generate` function with the following signature:

```python
def generate(payload, passcode, api_key="", key_order=None):
    """
    payload: dict (JSON data)
    passcode: str (Secret key/IV)
    api_key: str (Optional API key)
    key_order: list (Optional list of keys to sign)
    """
    import hashlib
    import hmac

    # Example: Simple concatenation
    data_str = ""
    # Use provided key order or default to sorted keys
    keys = key_order if key_order else sorted(payload.keys())
    
    for k in keys:
        data_str += str(payload.get(k, ""))
        
    # Create signature
    msg = api_key + data_str
    
    return hmac.new(passcode.encode(), msg.encode(), hashlib.sha256).hexdigest()
```