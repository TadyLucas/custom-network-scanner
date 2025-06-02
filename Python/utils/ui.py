def print_error(message):
    from utils.const import RED, BOLD, RESET
    print(f"""
╔══════════════════════════════════════════════╗
║ {RED}{BOLD}[✘] {message}{RESET}
╚══════════════════════════════════════════════╝{RESET}
""")
