def generate_listener(config):
    script_content = """
# Listener script content with all fixes
# ...
"""
    output_file = config["listener_file"]
    with open(output_file, "w") as f:
        f.write(script_content.format(
            # ... (format with config)
        ))

    print(f"[*] Generated listener: {output_file}")
