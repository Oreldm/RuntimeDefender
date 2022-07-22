import subprocess
class Tools:
    def terminal_command(self, command: str):
        ret = None
        try:
            ret = subprocess.check_output(command, shell=True)
        except:
            print(f"Command {command} return exit code 127")

        return ret
