import json
import os
import sys
import hashlib
import hmac
import base64
import time
import traceback

# Try to import customtkinter, fallback if not present (though user installed it)
try:
    import customtkinter as ctk
    HAS_CTK = True
except ImportError:
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext
    HAS_CTK = False

# --- Configuration ---
# Ensure snippets file is stored in the same directory as the script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SNIPPETS_FILE = os.path.join(SCRIPT_DIR, "snippets.json")
DEFAULT_THEME = "dark-blue"  # CustomTkinter theme

# --- Core Logic: Snippet Manager ---
class SnippetManager:
    def __init__(self, filepath):
        self.filepath = filepath
        self.snippets = {}
        self.load_snippets()

    def load_snippets(self):
        if not os.path.exists(self.filepath):
            self.create_default_snippets()
        try:
            with open(self.filepath, 'r') as f:
                self.snippets = json.load(f)
        except Exception as e:
            print(f"Error loading snippets: {e}")
            self.snippets = {}

    def save_snippets(self):
        try:
            with open(self.filepath, 'w') as f:
                json.dump(self.snippets, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving snippets: {e}")
            return False

    def get_snippet(self, name):
        return self.snippets.get(name)

    def get_all_names(self):
        return list(self.snippets.keys())

    def update_snippet(self, name, code, description=""):
        self.snippets[name] = {
            "code": code,
            "description": description
        }
        self.save_snippets()

    def delete_snippet(self, name):
        if name in self.snippets:
            del self.snippets[name]
            self.save_snippets()

    def create_default_snippets(self):
        # Porting the original ABA HMAC SHA256 logic as the default snippet
        default_code = """
def generate(payload, passcode, api_key="", key_order=None):
    import hmac
    import hashlib

    # 1. Parse Passcode
    if len(passcode) < 16:
        raise ValueError("PassCode must be at least 16 characters long.")
    iv = passcode[-16:]
    key = passcode[:-16]

    # 2. Concat API Key
    concat_str = api_key if api_key else ""

    # 3. Determine Keys to Sign
    keys_to_sign = []
    if key_order:
        # If explicit order provided, use it
        keys_to_sign = key_order
    else:
        # Default: all keys except 'hash' and special meta keys
        keys_to_sign = [k for k in payload.keys() if k != 'hash' and k != '__keys_order__']

    # 4. Concat Payload Values
    for k in keys_to_sign:
        val = payload.get(k)
        if val is None: val = ""
        concat_str += str(val)

    # 5. Create Message
    message = iv + concat_str

    # 6. Sign
    signature = hmac.new(
        key.encode('utf-8'), 
        message.encode('utf-8'), 
        hashlib.sha256
    ).hexdigest()
    
    return signature
"""
        self.snippets["ABA HMAC SHA256"] = {
            "code": default_code.strip(),
            "description": "Original ABA HMAC-SHA256 Implementation"
        }
        self.save_snippets()

# --- Core Logic: Crypto Engine ---
class CryptoEngine:
    @staticmethod
    def execute_snippet(snippet_code, payload, passcode, api_key="", key_order=None):
        """
        Executes the snippet code safely.
        The snippet MUST define a function `generate(payload, passcode, api_key, key_order)`.
        Wrapper handles backwards compatibility if key_order is missing in definition.
        """
        # define execution context
        local_scope = {}
        
        # Inject common modules to make life easier for the user
        global_scope = {
            "hashlib": hashlib,
            "hmac": hmac,
            "base64": base64,
            "json": json,
            "time": time
        }

        try:
            exec(snippet_code, global_scope, local_scope)
            
            if "generate" not in local_scope:
                raise ValueError("Snippet must define a 'generate' function.")
            
            generate_func = local_scope["generate"]
            
            # Simple inspection or try/catch to see if it accepts key_order? 
            # Or just assume updated signature. For robustness, let's try calling with it, if TypeError, call without.
            try:
                return generate_func(payload, passcode, api_key, key_order)
            except TypeError as te:
                if "positional argument" in str(te) or "argument" in str(te):
                     # Fallback for old snippets
                     return generate_func(payload, passcode, api_key)
                raise te
            
        except Exception as e:
            # Capture traceback for better debugging in UI
            return f"Error: {str(e)}\n{traceback.format_exc()}"
            
        except Exception as e:
            # Capture traceback for better debugging in UI
            return f"Error: {str(e)}\n{traceback.format_exc()}"

# --- UI Implementation (CustomTkinter) ---

class SnippetSelectionDialog(ctk.CTkToplevel):
    def __init__(self, parent, snippet_list):
        super().__init__(parent)
        self.selection = None
        self.title("Select Snippet to Load")
        self.geometry("400x500")
        self.lift() # Move to top
        self.focus_force()
        self.grab_set() # Make modal
        
        # Label
        ctk.CTkLabel(self, text="Available Snippets:", font=("Arial", 16)).pack(pady=10)

        # Scrollable frame for list
        self.scroll_frame = ctk.CTkScrollableFrame(self)
        self.scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        if not snippet_list:
            ctk.CTkLabel(self.scroll_frame, text="No snippets found.").pack(pady=20)
        
        for name in snippet_list:
            btn = ctk.CTkButton(self.scroll_frame, text=name, 
                                command=lambda n=name: self.on_select(n))
            btn.pack(fill="x", pady=2)
            
    def on_select(self, name):
        self.selection = name
        self.destroy()

    def get_input(self):
        self.wait_window()
        return self.selection

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("HashGen")
        self.geometry("1000x700")

        # Managers
        self.snippet_manager = SnippetManager(SNIPPETS_FILE)
        
        # Main Layout: 1 column, 1 row (Tabview takes all)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # TabView (Horizontal Navigation)
        self.tabview = ctk.CTkTabview(self, corner_radius=10)
        self.tabview.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        # Create Tabs
        self.tab_gen = self.tabview.add("Generator")
        self.tab_edit = self.tabview.add("Snippet Editor")
        
        # Populate Tabs
        self.setup_generator_tab(self.tab_gen)
        self.setup_editor_tab(self.tab_edit)

        # Appearance (Bottom Right or Menu? Let's put in Editor tab for now or just generic)
        # Or add a small button in corner? 
        # For simplicity, default to Dark.
        
    def setup_generator_tab(self, parent_frame):
        # Configure Grid on the TAB frame
        # Column 0: Inputs (Fixed width)
        # Column 1: Text Areas (Expandable)
        parent_frame.grid_columnconfigure(0, weight=0, minsize=300) 
        parent_frame.grid_columnconfigure(1, weight=1)
        parent_frame.grid_rowconfigure(0, weight=1) # Main content row

        # Create Left and Right frames inside the tab
        left_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        left_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        right_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        right_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        right_frame.grid_rowconfigure(1, weight=1) # Payload
        right_frame.grid_rowconfigure(3, weight=1) # Output
        right_frame.grid_columnconfigure(0, weight=1)

        # --- LEFT COLUMN (Inputs) ---
        
        # Algorithm
        ctk.CTkLabel(left_frame, text="Algorithm:", anchor="w").pack(fill="x", pady=(5,0))
        self.algo_var = ctk.StringVar()
        self.gen_algo_option = ctk.CTkOptionMenu(left_frame, variable=self.algo_var)
        self.gen_algo_option.pack(fill="x", pady=(5, 15))
        self.refresh_algo_list()

        # Passcode
        ctk.CTkLabel(left_frame, text="PassCode (Key+IV):", anchor="w").pack(fill="x", pady=(5,0))
        self.gen_passcode = ctk.CTkEntry(left_frame, placeholder_text="Enter passcode...")
        self.gen_passcode.pack(fill="x", pady=(5, 10))

        # API Key
        ctk.CTkLabel(left_frame, text="API Key (Optional):", anchor="w").pack(fill="x", pady=(5,0))
        self.gen_apikey = ctk.CTkEntry(left_frame, placeholder_text="Enter API Key...")
        self.gen_apikey.pack(fill="x", pady=(5, 10))

        # Keys Order
        ctk.CTkLabel(left_frame, text="Keys Order (comma separated):", anchor="w").pack(fill="x", pady=(5,0))
        self.gen_keys = ctk.CTkEntry(left_frame, placeholder_text="key1, key2, key3...")
        self.gen_keys.pack(fill="x", pady=(5, 20))

        # Generate Button
        self.btn_execute = ctk.CTkButton(left_frame, text="Generate Hash", height=50, font=("Arial", 16, "bold"), command=self.on_generate)
        self.btn_execute.pack(fill="x", pady=20)

        # --- RIGHT COLUMN (Text Areas) ---

        # JSON Payload
        ctk.CTkLabel(right_frame, text="JSON Payload:", anchor="w").grid(row=0, column=0, sticky="w", pady=(0,5))
        self.gen_payload = ctk.CTkTextbox(right_frame, height=150)
        self.gen_payload.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        self.gen_payload.insert("1.0", '{\n  "username": "user",\n  "request_time": "20260101010101"\n}')
        # Auto-actions bindings
        self.gen_payload.bind("<KeyRelease>", self.on_payload_change)
        self.gen_payload.bind("<FocusOut>", self.on_payload_focus_out)

        # Output
        ctk.CTkLabel(right_frame, text="Output:", anchor="w").grid(row=2, column=0, sticky="w", pady=(0,5))
        self.gen_output = ctk.CTkTextbox(right_frame, height=150)
        self.gen_output.grid(row=3, column=0, sticky="nsew", pady=(0, 0))

    def setup_editor_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(0, weight=1)
        parent_frame.grid_rowconfigure(2, weight=1) # Code area expands

        # Top Bar: Name and Actions
        top_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        top_frame.grid(row=0, column=0, padx=20, pady=20, sticky="ew")
        
        self.edit_name_entry = ctk.CTkEntry(top_frame, placeholder_text="Snippet Name")
        self.edit_name_entry.pack(side="left", fill="x", expand=True)
        
        ctk.CTkButton(top_frame, text="Save", width=100, command=self.on_save_snippet).pack(side="right", padx=5)
        # Load button moved to top bar
        ctk.CTkButton(top_frame, text="Load", width=100, command=self.on_load_snippet_into_editor).pack(side="right", padx=5)

        ctk.CTkLabel(parent_frame, text="Python Code (Must define 'generate(payload, passcode, api_key)'):", anchor="w").grid(row=1, column=0, padx=20, sticky="w")
        
        self.edit_code = ctk.CTkTextbox(parent_frame, font=("Courier", 14))
        self.edit_code.grid(row=2, column=0, padx=20, pady=(5, 20), sticky="nsew")
        
        # Default template
        default_template = """
def generate(payload, passcode, api_key="", key_order=None):
    import hashlib
    # Implement your logic here
    # key_order is a list of keys if provided by user
    return "hash_result"
"""
        self.edit_code.insert("1.0", default_template.strip())

    # --- Actions ---

    def on_payload_change(self, event=None):
        """Called on every key release in payload box. Tries to extract keys silently."""
        self._try_extract_keys(silent=True)

    def on_payload_focus_out(self, event=None):
        """Called when user leaves payload box. Formats JSON and extracts keys."""
        self._try_format_json()
        self._try_extract_keys(silent=False) # Report errors on explicit focus out? or keep silent? silent is better UX.
        # Actually, let's keep silent unless it's a critical logic step, but for focus out, quiet is good.

    def _try_extract_keys(self, silent=True):
        try:
            payload_str = self.gen_payload.get("1.0", "end").strip()
            if not payload_str: return

            data = json.loads(payload_str)
            if isinstance(data, dict):
                keys = [k for k in data.keys() if k != 'hash']
                current_keys = self.gen_keys.get().strip()
                new_keys_str = ", ".join(keys)
                
                # Only update if different and not empty (to avoid overwriting user manual edits if they are valid? 
                # Actually user asked for auto-extract. Let's overwrite IF valid JSON is detected.)
                # Checks if we should overwrite: If the JSON changed, we probably should update keys.
                # But to avoid fighting the user if they are typing keys manually?
                # The prompt says: "auto extract after paste". 
                # Simplest IS to overwrite if payload > keys.
                
                if current_keys != new_keys_str:
                    self.gen_keys.delete(0, "end")
                    self.gen_keys.insert(0, new_keys_str)
        except:
            pass # Silent fail during typing is normal

    def _try_format_json(self):
        try:
            payload_str = self.gen_payload.get("1.0", "end").strip()
            if not payload_str: return
            
            data = json.loads(payload_str)
            formatted = json.dumps(data, indent=2)
            
            # Avoid full replace if identical (prevents cursor jump / unnecessary redraw if just clicked in/out)
            if formatted != payload_str:
                self.gen_payload.delete("1.0", "end")
                self.gen_payload.insert("1.0", formatted)
        except:
            pass

    def refresh_algo_list(self):
        names = self.snippet_manager.get_all_names()
        if not names: names = ["Default"]
        self.gen_algo_option.configure(values=names)
        if not self.algo_var.get() in names:
            self.algo_var.set(names[0])

    def on_generate(self):
        name = self.algo_var.get()
        snippet = self.snippet_manager.get_snippet(name)
        if not snippet:
             self.gen_output.delete("1.0", "end")
             self.gen_output.insert("1.0", "Error: No snippet selected.")
             return

        try:
            payload_str = self.gen_payload.get("1.0", "end").strip()
            payload = json.loads(payload_str)
            passcode = self.gen_passcode.get()
            apikey = self.gen_apikey.get()
            
            keys_str = self.gen_keys.get().strip()
            key_order = [k.strip() for k in keys_str.split(',') if k.strip()] if keys_str else None

            result = CryptoEngine.execute_snippet(snippet["code"], payload, passcode, apikey, key_order)
            
            self.gen_output.delete("1.0", "end")
            self.gen_output.insert("1.0", str(result))
        except json.JSONDecodeError:
            self.gen_output.delete("1.0", "end")
            self.gen_output.insert("1.0", "Error: Invalid JSON Payload")
        except Exception as e:
            self.gen_output.delete("1.0", "end")
            self.gen_output.insert("1.0", f"Error: {str(e)}")

    def on_save_snippet(self):
        name = self.edit_name_entry.get().strip()
        code = self.edit_code.get("1.0", "end").strip()
        
        if not name:
            self.edit_name_entry.configure(placeholder_text="NAME REQUIRED!")
            return

        self.snippet_manager.update_snippet(name, code)
        self.refresh_algo_list() # Update dropdown if name is new

    def on_load_snippet_into_editor(self):
        names = self.snippet_manager.get_all_names()
        dialog = SnippetSelectionDialog(self, names)
        name = dialog.get_input()
        
        if name:
            snippet = self.snippet_manager.get_snippet(name)
            if snippet:
                self.edit_name_entry.delete(0, "end")
                self.edit_name_entry.insert(0, name)
                self.edit_code.delete("1.0", "end")
                self.edit_code.insert("1.0", snippet["code"])
            else:
                pass # Not found

if __name__ == "__main__":
    if HAS_CTK:
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")
    
    app = App()
    app.mainloop()
